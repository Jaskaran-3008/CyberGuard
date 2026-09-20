from sklearn.ensemble import RandomForestClassifier


# Training data
# [failed_attempts, unique_ips, login_failure_ratio]

X = [
    [0, 1, 0.00],
    [1, 1, 0.10],
    [2, 1, 0.20],
    [1, 2, 0.10],
    [2, 2, 0.20],
    [3, 2, 0.25],
    [4, 1, 0.40],
    [5, 1, 0.50],
    [6, 1, 0.60],
    [7, 1, 0.70],
    [8, 1, 0.80],
    [10, 1, 0.90]
]


# 0 = Normal
# 1 = Suspicious

y = [
    0,
    0,
    0,
    0,
    0,
    0,
    1,
    1,
    1,
    1,
    1,
    1
]


# Create the machine learning model

model = RandomForestClassifier(
    n_estimators=50,
    random_state=42
)


# Train the model

model.fit(X, y)


def predict_risk(failed_attempts, unique_ips, failure_ratio):

    prediction = model.predict([
        [failed_attempts, unique_ips, failure_ratio]
    ])[0]

    probability = model.predict_proba([
        [failed_attempts, unique_ips, failure_ratio]
    ])[0][1]

    risk_score = round(probability * 100)

    if prediction == 1:
        threat_level = "HIGH"
    else:
        threat_level = "LOW"

    return {
        "prediction": "Suspicious" if prediction == 1 else "Normal",
        "risk_score": risk_score,
        "threat_level": threat_level
    }

if __name__ == "__main__":

    result = predict_risk(
        failed_attempts=5,
        unique_ips=1,
        failure_ratio=0.5
    )

    print(result)