import time
from src.signet.controller.monitor import monitor

def test_ewma_error_and_latency():
    # Reset by creating local snapshot baseline (not clearing global; rely on new route)
    route = '/t1'
    # emit successes
    for _ in range(5):
        monitor.emit({
            'pch_present': True, 'pch_verified': True, 'failure_reason': 'none',
            'header_total_bytes': 100, 'largest_header_bytes': 50, 'signature_bytes': 40,
            'latency_ms': 10.0, 'http_status': 200, 'is_guarded_route': False,
            'tls_binding_header_present': True, 'route': route
        })
    base = monitor.snapshot(route)['route_stats']
    err0 = base['ewma_error_rate']
    lat0 = base['ewma_latency_ms']
    # inject failures with higher latency
    for _ in range(3):
        monitor.emit({
            'pch_present': True, 'pch_verified': False, 'failure_reason': 'bad_signature',
            'header_total_bytes': 120, 'largest_header_bytes': 60, 'signature_bytes': 55,
            'latency_ms': 30.0, 'http_status': 200, 'is_guarded_route': False,
            'tls_binding_header_present': True, 'route': route
        })
    after = monitor.snapshot(route)['route_stats']
    assert after['ewma_error_rate'] > err0
    assert after['ewma_latency_ms'] > lat0


def test_header_431_spike_anomaly():
    route = '/t431'
    # Generate baseline few 431
    for _ in range(3):
        monitor.emit({
            'pch_present': True, 'pch_verified': False, 'failure_reason': 'header_budget',
            'header_total_bytes': 90000, 'largest_header_bytes': 45000, 'signature_bytes': 10,
            'latency_ms': 5.0, 'http_status': 431, 'is_guarded_route': True,
            'tls_binding_header_present': True, 'route': route
        })
    # Spike
    for _ in range(10):
        monitor.emit({
            'pch_present': True, 'pch_verified': False, 'failure_reason': 'header_budget',
            'header_total_bytes': 91000, 'largest_header_bytes': 45000, 'signature_bytes': 10,
            'latency_ms': 5.0, 'http_status': 431, 'is_guarded_route': True,
            'tls_binding_header_present': True, 'route': route
        })
    snap = monitor.snapshot()
    assert snap['anomalies']['header_431_spike'] is True


def test_kingman_queue_increases_with_variance():
    route = '/tq'
    # Low variance arrivals and service
    for _ in range(20):
        monitor.emit({
            'pch_present': True, 'pch_verified': True, 'failure_reason': 'none',
            'header_total_bytes': 100, 'largest_header_bytes': 50, 'signature_bytes': 40,
            'latency_ms': 10.0, 'http_status': 200, 'is_guarded_route': False,
            'tls_binding_header_present': True, 'route': route
        })
        time.sleep(0.005)
    low = monitor.snapshot(route)['route_stats']['kingman_wq_ms']
    # Introduce higher variance in latency and inter-arrival
    for i in range(30):
        monitor.emit({
            'pch_present': True, 'pch_verified': True, 'failure_reason': 'none',
            'header_total_bytes': 100, 'largest_header_bytes': 50, 'signature_bytes': 40,
            'latency_ms': 5.0 + (i % 5) * 15.0, 'http_status': 200, 'is_guarded_route': False,
            'tls_binding_header_present': True, 'route': route
        })
        if i % 5 == 0:
            time.sleep(0.02)
        else:
            time.sleep(0.001)
    high = monitor.snapshot(route)['route_stats']['kingman_wq_ms']
    assert high >= low
