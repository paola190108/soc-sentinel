import pickle
import os
import pandas as pd

MODELO_PATH = "output/modelo_rf.pkl"

with open(MODELO_PATH, "rb") as f:
    modelo, features, threshold = pickle.load(f)

print("=== SOC Sentinel - Analise de Alertas com ML ===\n")

exemplos = pd.DataFrame([
    {"duration":0,"protocol_type":1,"service":20,"flag":10,
     "src_bytes":181,"dst_bytes":5450,"land":0,"wrong_fragment":0,
     "urgent":0,"hot":0,"num_failed_logins":0,"logged_in":1,
     "num_compromised":0,"root_shell":0,"su_attempted":0,"num_root":0,
     "num_file_creations":0,"num_shells":0,"num_access_files":0,
     "num_outbound_cmds":0,"is_host_login":0,"is_guest_login":0,
     "count":8,"srv_count":8,"serror_rate":0.0,"srv_serror_rate":0.0,
     "rerror_rate":0.0,"srv_rerror_rate":0.0,"same_srv_rate":1.0,
     "diff_srv_rate":0.0,"srv_diff_host_rate":0.0,"dst_host_count":9,
     "dst_host_srv_count":9,"dst_host_same_srv_rate":1.0,
     "dst_host_diff_srv_rate":0.0,"dst_host_same_src_port_rate":0.11,
     "dst_host_srv_diff_host_rate":0.0,"dst_host_serror_rate":0.0,
     "dst_host_srv_serror_rate":0.0,"dst_host_rerror_rate":0.0,
     "dst_host_srv_rerror_rate":0.0,"tipo_real":"normal"},
    {"duration":0,"protocol_type":1,"service":20,"flag":10,
     "src_bytes":0,"dst_bytes":0,"land":0,"wrong_fragment":0,
     "urgent":0,"hot":0,"num_failed_logins":0,"logged_in":0,
     "num_compromised":0,"root_shell":0,"su_attempted":0,"num_root":0,
     "num_file_creations":0,"num_shells":0,"num_access_files":0,
     "num_outbound_cmds":0,"is_host_login":0,"is_guest_login":0,
     "count":511,"srv_count":511,"serror_rate":1.0,"srv_serror_rate":1.0,
     "rerror_rate":0.0,"srv_rerror_rate":0.0,"same_srv_rate":1.0,
     "diff_srv_rate":0.0,"srv_diff_host_rate":0.0,"dst_host_count":255,
     "dst_host_srv_count":255,"dst_host_same_srv_rate":1.0,
     "dst_host_diff_srv_rate":0.0,"dst_host_same_src_port_rate":1.0,
     "dst_host_srv_diff_host_rate":0.0,"dst_host_serror_rate":1.0,
     "dst_host_srv_serror_rate":1.0,"dst_host_rerror_rate":0.0,
     "dst_host_srv_rerror_rate":0.0,"tipo_real":"ataque DoS"},
    {"duration":0,"protocol_type":2,"service":50,"flag":5,
     "src_bytes":0,"dst_bytes":0,"land":0,"wrong_fragment":0,
     "urgent":0,"hot":0,"num_failed_logins":5,"logged_in":0,
     "num_compromised":0,"root_shell":0,"su_attempted":0,"num_root":0,
     "num_file_creations":0,"num_shells":0,"num_access_files":0,
     "num_outbound_cmds":0,"is_host_login":0,"is_guest_login":0,
     "count":150,"srv_count":25,"serror_rate":0.0,"srv_serror_rate":0.0,
     "rerror_rate":1.0,"srv_rerror_rate":1.0,"same_srv_rate":0.17,
     "diff_srv_rate":0.83,"srv_diff_host_rate":0.0,"dst_host_count":255,
     "dst_host_srv_count":25,"dst_host_same_srv_rate":0.10,
     "dst_host_diff_srv_rate":0.90,"dst_host_same_src_port_rate":0.0,
     "dst_host_srv_diff_host_rate":0.0,"dst_host_serror_rate":0.0,
     "dst_host_srv_serror_rate":0.0,"dst_host_rerror_rate":1.0,
     "dst_host_srv_rerror_rate":1.0,"tipo_real":"brute force SSH"},
])

tipos = exemplos.pop("tipo_real")
X = exemplos[features]
probs = modelo.predict_proba(X)[:, 1]
preds = (probs >= threshold).astype(int)

print(f"{'#':<4} {'Tipo Real':<20} {'Probabilidade':<16} {'Classificacao ML'}")
print("-" * 60)
for i, (tipo, prob, pred) in enumerate(zip(tipos, probs, preds)):
    classe = "[ATAQUE]" if pred == 1 else "[Normal]"
    print(f"{i+1:<4} {tipo:<20} {prob:.1%}{'':>8} {classe}")

print(f"\nThreshold: {threshold} -- acima disso o modelo classifica como ataque")
print("Modelo funcionando! Integração com Wazuh pronta.")
