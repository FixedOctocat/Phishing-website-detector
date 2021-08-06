import pandas as pd
import numpy as np
import seaborn as sns
import matplotlib.pyplot as plt

data0 = pd.read_csv('data/5.urldata.csv')

print(data0.head())
print(data0.columns)
print(data0.info())

plt.figure(figsize=(15,13))
sns.heatmap(data0.corr())
plt.show()

print(data0.describe())

data = data0.drop(['Domain'], axis = 1).copy()
data = data.sample(frac=1).reset_index(drop=True)



# Sepratating & assigning features and target columns to X & y
y = data['Label']
X = data.drop('Label',axis=1)

from sklearn.model_selection import train_test_split

X_train, X_test, y_train, y_test = train_test_split(X, y,
                                                    test_size = 0.2, random_state = 12)



#importing packages
from sklearn.metrics import accuracy_score

ML_Model = []
acc_train = []
acc_test = []

#function to call for storing the results
def storeResults(model, a,b):
  ML_Model.append(model)
  acc_train.append(round(a, 3))
  acc_test.append(round(b, 3))





#XGBoost Classification model
from xgboost import XGBClassifier

# instantiate the model
xgb = XGBClassifier(learning_rate=0.8,max_depth=17)
#fit the model
xgb.fit(X_train, y_train)
xgb.save_model("xgb.model")





#predicting the target value from the model for the samples
y_test_xgb = xgb.predict(X_test)
y_train_xgb = xgb.predict(X_train)



#computing the accuracy of the model performance
acc_train_xgb = accuracy_score(y_train,y_train_xgb)
acc_test_xgb = accuracy_score(y_test,y_test_xgb)

print("XGBoost: Accuracy on training Data: {:.3f}".format(acc_train_xgb))
print("XGBoost : Accuracy on test Data: {:.3f}".format(acc_test_xgb))



#storing the results. The below mentioned order of parameter passing is important.
#Caution: Execute only once to avoid duplications.
storeResults('XGBoost', acc_train_xgb, acc_test_xgb)




