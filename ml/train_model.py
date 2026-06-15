"""
SOC Sentinel - Modelo de Detecção de Ameaças v2
================================================
Melhorias:
- class_weight balanceado para dar mais peso a ataques
- mais estimadores
- threshold ajustado para priorizar recall
"""

import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
from sklearn.preprocessing import LabelEncoder
import matplotlib.pyplot as plt
import seaborn as sns
import pickle
import os
import numpy as np

COLUNAS = [
    "duration", "protocol_type", "service", "flag",
    "src_bytes", "dst_bytes", "land", "wrong_fragment", "urgent",
    "hot", "num_failed_logins", "logged_in", "num_compromised",
    "root_shell", "su_attempted", "num_root", "num_file_creations",
    "num_shells", "num_access_files", "num_outbound_cmds",
    "is_host_login", "is_guest_login", "count", "srv_count",
    "serror_rate", "srv_serror_rate", "rerror_rate", "srv_rerror_rate",
    "same_srv_rate", "diff_srv_rate", "srv_diff_host_rate",
    "dst_host_count", "dst_host_srv_count", "dst_host_same_srv_rate",
    "dst_host_diff_srv_rate", "dst_host_same_src_port_rate",
    "dst_host_srv_diff_host_rate", "dst_host_serror_rate",
    "dst_host_srv_serror_rate", "dst_host_rerror_rate",
    "dst_host_srv_rerror_rate", "label", "difficulty"
]

print("Carregando dataset...")
train = pd.read_csv("data/KDDTrain+.txt", names=COLUNAS)
test  = pd.read_csv("data/KDDTest+.txt",  names=COLUNAS)

train["target"] = train["label"].apply(lambda x: 0 if x == "normal" else 1)
test["target"]  = test["label"].apply(lambda x: 0 if x == "normal" else 1)

le = LabelEncoder()
for col in ["protocol_type", "service", "flag"]:
    train[col] = le.fit_transform(train[col])
    test[col]  = le.fit_transform(test[col])

FEATURES = [c for c in COLUNAS if c not in ["label", "difficulty", "target"]]
X_train = train[FEATURES]
y_train = train["target"]
X_test  = test[FEATURES]
y_test  = test["target"]

print("Treinando Random Forest v2...")
modelo = RandomForestClassifier(
    n_estimators=200,
    max_depth=30,
    class_weight={0: 1, 1: 2},  # peso dobrado para ataques
    random_state=42,
    n_jobs=-1
)
modelo.fit(X_train, y_train)

# ── THRESHOLD AJUSTADO ────────────────────────────────────────────────────────
# Em vez de usar 0.5 como padrão, usamos 0.3:
# se o modelo acha que tem 30% de chance de ser ataque, já alerta.
# Isso aumenta o recall (detecta mais ataques) às custas de mais falsos positivos.
probabilidades = modelo.predict_proba(X_test)[:, 1]
THRESHOLD = 0.3
y_pred = (probabilidades >= THRESHOLD).astype(int)

acc = accuracy_score(y_test, y_pred)
print(f"\nAcurácia: {acc:.2%}")
print(f"Threshold usado: {THRESHOLD}")
print("\nRelatório completo:")
print(classification_report(y_test, y_pred, target_names=["Normal", "Ataque"]))

os.makedirs("output", exist_ok=True)

cm = confusion_matrix(y_test, y_pred)
plt.figure(figsize=(6, 5))
sns.heatmap(cm, annot=True, fmt="d", cmap="Blues",
            xticklabels=["Normal", "Ataque"],
            yticklabels=["Normal", "Ataque"])
plt.title("Matriz de Confusão v2 — SOC Sentinel")
plt.ylabel("Real")
plt.xlabel("Previsto")
plt.tight_layout()
plt.savefig("output/confusion_matrix.png", dpi=150)

importancias = pd.Series(modelo.feature_importances_, index=FEATURES)
top10 = importancias.nlargest(10)
plt.figure(figsize=(8, 5))
ax = sns.barplot(x=top10.values, y=top10.index, hue=top10.index,
                 palette="viridis", legend=False)
plt.title("Top 10 Features Mais Importantes")
plt.xlabel("Importância")
plt.tight_layout()
plt.savefig("output/feature_importance.png", dpi=150)

with open("output/modelo_rf.pkl", "wb") as f:
    pickle.dump((modelo, FEATURES, THRESHOLD), f)

print("\nGráficos e modelo salvos em output/")
