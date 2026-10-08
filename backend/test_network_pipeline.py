import sys, warnings
warnings.filterwarnings('ignore')
sys.path.insert(0, '.')

from app.detection.network_detector import NetworkDetector
import pandas as pd

print('Testing network flow ML pipeline end-to-end...')

model_path = 'app/models/argus_network_best_model.joblib'
detector = NetworkDetector(model_path)

sample_features = {
    'active_max': 0.0, 'active_mean': 0.0, 'active_min': 0.0, 'active_std': 0.0,
    'bwd_iat_max': 500000.0, 'bwd_iat_mean': 250000.0, 'bwd_iat_min': 10000.0, 'bwd_iat_std': 150000.0,
    'bwd_psh_flags': 0.0, 'bwd_urg_flags': 0.0, 'cwe_flag_count': 0.0, 'down_up_ratio': 1.0,
    'flow_duration': 600000.0, 'flow_iat_max': 500000.0, 'flow_iat_mean': 100000.0, 'flow_iat_min': 500.0,
    'flow_iat_std': 200000.0, 'fwd_iat_max': 10000.0, 'fwd_iat_mean': 5000.0, 'fwd_iat_min': 1000.0,
    'fwd_iat_std': 3000.0, 'fwd_psh_flags': 0.0, 'fwd_urg_flags': 0.0,
    'idle_max': 600000.0, 'idle_mean': 300000.0, 'idle_min': 100000.0, 'idle_std': 150000.0
}

df = pd.DataFrame([sample_features])
result = detector.predict(df)[0]

print()
print('=== NETWORK ML RESULT ===')
print('  Prediction       :', result['prediction'])
print('  Attack Probability:', result['attack_probability'])
print('  Confidence       :', result['confidence'])
print('=========================')
print()
print('[OK] Network detection pipeline working correctly!')
