import os
import pandas as pd
import numpy as np
import seaborn as sns
import matplotlib.pyplot as plt

from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score
from xgboost import XGBClassifier

from modules.ml.features import Features


def train():

    data0 = pd.read_csv('modules/ml/data/fishing_dataset.csv')

    print(data0.head())
    print(data0.columns)
    print(data0.info())

    plt.figure(figsize=(15,13))
    sns.heatmap(data0.corr())
    plt.show()

    print(data0.describe())

    data = data0.drop(['id'], axis = 1).copy()
    data = data.sample(frac=1).reset_index(drop=True)

    # Separating & assigning features and target columns to X & y
    y = data['Result']
    data = data.drop('Result', axis=1)

    # Drop unavailable features
    data = data.drop('URL_of_Anchor', axis=1)
    data = data.drop('Links_in_tags', axis=1)
    data = data.drop('SFH', axis=1)
    data = data.drop('Request_URL', axis=1)
    X = data.drop('Abnormal_URL', axis=1)

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size = 0.2, random_state = 12)

    xgb = XGBClassifier(learning_rate=0.2, max_depth=40)
    xgb.fit(X_train, y_train)
    xgb.save_model("xgb.model")

    # Predicting the target value from the model for the samples
    y_test_xgb = xgb.predict(X_test)
    y_train_xgb = xgb.predict(X_train)

    # Computing the accuracy of the model performance
    acc_train_xgb = accuracy_score(y_train, y_train_xgb)
    acc_test_xgb = accuracy_score(y_test, y_test_xgb)

    print("XGBoost: Accuracy on training Data: {:.3f}".format(acc_train_xgb))
    print("XGBoost : Accuracy on test Data: {:.3f}".format(acc_test_xgb))


def train2():
    data0 = pd.read_csv('data/fishing_dataset.csv')

    print(data0.head())
    print(data0.columns)
    print(data0.info())

    plt.figure(figsize=(15, 13))
    sns.heatmap(data0.corr())
    plt.show()

    print(data0.describe())

    data = data0.drop(['id'], axis=1).copy()
    data = data.sample(frac=1).reset_index(drop=True)

    # Separating & assigning features and target columns to X & y
    y = data['Result']
    data = data.drop('Result', axis=1)

    # Drop unavailable features
    data = data.drop('URL_of_Anchor', axis=1)
    data = data.drop('Links_in_tags', axis=1)
    data = data.drop('SFH', axis=1)
    data = data.drop('Request_URL', axis=1)
    X = data.drop('Abnormal_URL', axis=1)

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=12)

    # Multilayer Perceptrons model
    from sklearn.neural_network import MLPClassifier

    # instantiate the model
    mlp = MLPClassifier(alpha=0.001, hidden_layer_sizes=([100, 100, 100]))

    # fit the model
    mlp.fit(X_train, y_train)

    # predicting the target value from the model for the samples
    y_test_mlp = mlp.predict(X_test)
    y_train_mlp = mlp.predict(X_train)

    #computing the accuracy of the model performance
    acc_train_mlp = accuracy_score(y_train,y_train_mlp)
    acc_test_mlp = accuracy_score(y_test,y_test_mlp)

    print("Multilayer Perceptrons: Accuracy on training Data: {:.3f}".format(acc_train_mlp))
    print("Multilayer Perceptrons: Accuracy on test Data: {:.3f}".format(acc_test_mlp))

    X_new = build_features("https://xn-----7kcbkbajnashi5aj7aees9aa4anc7u1c.xn--p1ai/").get_features()
    X_new = np.array(X_new).reshape(1, -1)

    print(mlp.predict(X_new))



def build_features(url):
    return Features(url)


def predict(url, features=None):

    if features:
        X_new = features.get_features()
    else:
        X_new = build_features(url).get_features()

    if not os.path.exists('xgb.model'):
        train()

    xgb = XGBClassifier(learning_rate=0.5, max_depth=40)
    xgb.load_model('xgb.model')

    X_new = np.array(X_new).reshape(1, -1)

    return xgb.predict(X_new)


train2()
# url = 'https://testnacovid-gosuslugi.ru/'
# url = 'https://yandex.ru/'
# f = build_features(url)
# p = predict(url, f)
# print(p)
# if p == Features.PHISHING:
#     print('Phishing')
# else:
#     print('Not phishing')
# print(f.get_features(True))
