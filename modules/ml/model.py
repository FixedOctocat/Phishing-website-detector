import os
import pandas as pd
import numpy as np
import seaborn as sns
import matplotlib.pyplot as plt

from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score
from xgboost import XGBClassifier

from features import Features


def train():

    data0 = pd.read_csv('data/fishing_dataset.csv')

    print(data0.head())
    print(data0.columns)
    print(data0.info())

    plt.figure(figsize=(15,13))
    sns.heatmap(data0.corr())
    plt.show()

    print(data0.describe())

    data = data0.drop(['id'], axis = 1).copy()
    data = data.sample(frac=1).reset_index(drop=True)

    # Sepratating & assigning features and target columns to X & y
    y = data['Result']
    X = data.drop('Result', axis=1)

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size = 0.2, random_state = 12)

    xgb = XGBClassifier(learning_rate=0.8, max_depth=17)
    xgb.fit(X_train, y_train)
    xgb.save_model("xgb.model")

    #predicting the target value from the model for the samples
    y_test_xgb = xgb.predict(X_test)
    y_train_xgb = xgb.predict(X_train)

    #computing the accuracy of the model performance
    acc_train_xgb = accuracy_score(y_train, y_train_xgb)
    acc_test_xgb = accuracy_score(y_test, y_test_xgb)

    print("XGBoost: Accuracy on training Data: {:.3f}".format(acc_train_xgb))
    print("XGBoost : Accuracy on test Data: {:.3f}".format(acc_test_xgb))


def predict(url):
    X_input = url
    X_new = Features(X_input).get_features()

    if not os.path.exists('xgb.model'):
        train()

    xgb = XGBClassifier(learning_rate=0.4, max_depth=7)
    xgb.load_model('xgb.model')

    X_new = np.array(X_new).reshape(1, -1)

    return xgb.predict(X_new)
