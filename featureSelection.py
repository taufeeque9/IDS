import pandas as pd
import numpy as np
import seaborn as sns
from sklearn.feature_selection import SelectKBest
from sklearn.feature_selection import chi2
from sklearn.preprocessing import LabelEncoder

dataset = pd.read_csv("MachineLearningCVE/Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv")

# print(dataset.isnull().sum())
new_data = dataset.dropna(axis=0, how='any', inplace=False)

y = new_data[[' Label']]
X = new_data.drop([' Label'], axis=1, inplace=False)
X_new = X

labelEncoder = LabelEncoder()
y = labelEncoder.fit_transform(y)
for col in X.columns:
    X_new[col] = labelEncoder.fit_transform(X[col])

# Features needed can be changed below to get the top 'k'
# features for model training

features_needed = 15

######################################################################

print("Selection based on Pearson Correlation")


def cor_selector(X, y, num_feats):
    cor_list = []
    feature_name = X.columns.tolist()
    # calculate the correlation with y for each feature
    for i in X.columns.tolist():
        cor = np.corrcoef(X[i], y)[0, 1]
        cor_list.append(cor)
    # replace NaN with 0
    cor_list = [0 if np.isnan(i) else i for i in cor_list]
    # feature name
    cor_feature = X.iloc[:, np.argsort(np.abs(cor_list))[-num_feats:]].columns.tolist()
    # feature selection? 0 for not select, 1 for select
    cor_support = [True if i in cor_feature else False for i in feature_name]
    return cor_support, cor_feature


cor_support, cor_feature = cor_selector(X_new, y, features_needed)
print(str(len(cor_feature)), 'selected features')
print(cor_feature)

#####################################################################

print("Selection based on chi square distibution")

chi_selector = SelectKBest(chi2, k=features_needed)
X_kbest_features = chi_selector.fit_transform(X_new, y)
chi_support = chi_selector.get_support()
chi_feature = X_new.loc[:, chi_support].columns.tolist()
print(str(len(chi_feature)), 'selected features')
print(chi_feature)


# # More Raw Approach - Leaving the first 2 valued and
# # last NaN valued features, all other features are
# # dependent and can be considered for training

# print("Raw Approach of chi square")
# chi_scores = chi2(X_new,y)
# p_values = pd.Series(chi_scores[1],index = X_new.columns)
# p_values.sort_values(ascending = False , inplace = True)
# # p_values.plot.bar()
# # print(p_values)
