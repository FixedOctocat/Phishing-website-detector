import feature_extract
import numpy as np


def train():
    pass


def predict(url):
    from xgboost import XGBClassifier

    # instantiate the model
    xgb = XGBClassifier(learning_rate=0.4, max_depth=7)
    xgb.load_model('xgb.model')

    X_input = url
    X_new = feature_extract.featureExtraction(X_input)
    X_new = np.array(X_new).reshape(1, -1)

    prediction = xgb.predict(X_new)
    if prediction == -1:
        print("Phish")
    else:
        print("Not phish")

predict("extratorrent.cc")