import pandas as pd
import numpy as np
from glob import glob
from sklearn import preprocessing
from sklearn.preprocessing import LabelEncoder
from sklearn.model_selection import train_test_split


def combine_csv():
    stock_files = sorted(glob('Dataset/*.pcap_ISCX.csv'))
    ids = pd.read_csv(stock_files[0])
    for i in range(1, len(stock_files)):
        dfi = pd.read_csv(stock_files[i])
        dfi.dropna(axis=0, how='any', inplace=True)
        ids = pd.concat((ids, dfi), ignore_index=True)

    del dfi
    print(ids.head())
    print(ids.head())
    ids.to_csv('Dataset/combined_data.csv', index=False)


def resize_dataset():
    ids = pd.read_csv('./Dataset/combined_data.csv')
    labels_to_drop = {'BENIGN': 0.1, 'DoS Hulk': 0.3, 'DDoS': 0.3, 'PortScan': 0.3}
    for label in labels_to_drop:
        df = ids.loc[ids[' Label'] == label]
        ids.drop(ids.index[ids[' Label'] == label], inplace=True)
        df = df.sample(frac=labels_to_drop[label])
        ids = pd.concat((ids, df), ignore_index=True)

    ids = ids.sample(frac=1)
    ids.reset_index(drop=True, inplace=True)
    # ids.to_csv('./Dataset/resized_data.csv')
    return ids


def binary_label_encoder(y):
    '''
    converts multiclass labels to binary labels
    '''
    pass


def split_dataset(df):
    '''
    Takes a dataframe df and splits it in 0.7:0.15:0.15 ratio for training, cross-validation and test sets.
    '''
    pass


# y = new_data[[' Label']]  # adding labels to y
# X = new_data.drop([' Label'], axis=1, inplace=False)  # dropping labels from new_data to form X
# X_new = X
#
#
# # converts the categorical data to numeric data for easier handling
# labelEncoder = LabelEncoder()  # creating an instance of label encoder, the methods will not get attached to it
# y = labelEncoder.fit_transform(y)
# for col in X.columns:
#     X_new[col] = labelEncoder.fit_transform(X[col])
#
# Y = pd.DataFrame(y)  # converting y into dataframe
#
#
def preprocessing(X, Y):
    '''
    Takes dataframes as inputs and outputs processed numpy arrays
    '''
    # Normalizing all the features
    norma_X = preprocessing.normalize(X)
    # OR
    # Standardizing all the features
    # standardized_X = preprocessing.scale(X)
    np.set_printoptions(precision=3)

    # df = ids.sample(frac=1) # randomly shuffling the dataset to ensure uniformity
    # after normalizing, we'll split the dataset

    # using stratified
    skf = StratifiedKFold(n_splits=10, random_state=None)
    skf.get_n_splits(X, Y)

    for train_index, test_index in skf.split(X, y):
        print("Train:", train_index, "Validation:", test_index)
        xTrain, xTest = X.iloc[train_index], X.iloc[test_index]
        yTrain, yTest = Y.iloc[train_index], Y.iloc[test_index]
        '''
        accuracy=[]
        classifier.fit(xTrain, yTrain)
        prediction = classifier.predicted(xTest)
        score = accuracy_score(prediction, yTest)
        accuracy.append(score)
        print(accuracy)
        '''
    # splitting the data in 80:20 train:test ratio
    # xTrain, xTest, yTrain, yTest = train_test_split(norma_X, y, test_size = 0.2, random_state = 0)

    # covnvert arrays into dataframes
    xtrain = pd.DataFrame(xTrain)
    xtest = pd.DataFrame(xTest)
    ytrain = pd.DataFrame(yTrain)
    ytest = pd.DataFrame(yTest)

    return xtrain, xtest, ytrain, ytest


xTrainn, xTestt, yTrainn, yTestt = preprocessing(X_new, Y)
