from src.signet.controller.plan import set_utility_context, plan
from src.signet.controller.state import load_state, save_state
import json
ROUTE='/protected'
s=load_state(ROUTE)
s.name='Closed'
save_state(ROUTE,s)
set_utility_context({'availability_floor_5xx_ewma':0.10,'ewma_5xx':0.02,'header_budget_total':8000,'header_total_bytes':2000,'alpha':0.5,'beta':0.3,'gamma':0.2,'pqc_rate':0.9,'failure_rate':0.40,'slo_headroom':0.4,'fallback_pqc_rate':0.4,'fallback_failure_rate':0.10,'fallback_slo_headroom':0.5})
print(json.dumps(plan(ROUTE), indent=2))
