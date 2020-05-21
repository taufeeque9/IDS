'''
import pandas as pd
from glob import glob
stock_files = sorted(glob('data/data_*.csv')) #rename the data sets to get similar name so that we can iterate properly
stock_files
pd.concat((pd.read_csv(file).assign(filename = file)
         for file in stock_files), ignore_index = True)
# this is showing memory error in my laptop due to less ram storage, hopefully this will work in yours.
'''


import pandas as pd
import numpy as np
from sklearn import preprocessing
from sklearn.preprocessing import LabelEncoder
from sklearn.model_selection import train_test_split

ids = pd.read_csv('./Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv')
new_data = ids.dropna(axis = 0, how ='any', inplace=False)

y = new_data[[' Label']] # adding labels to y
X = new_data.drop([' Label'], axis=1, inplace=False) # dropping labels from new_data to form X
X_new = X


# converts the categorical data to numeric data for easier handling 
labelEncoder = LabelEncoder() # creating an instance of label encoder, the methods will not get attached to it
y = labelEncoder.fit_transform(y)
for col in X.columns:
    X_new[col] = labelEncoder.fit_transform(X[col])
    
def preprocessing(X_new, y):
    import pandas as pd
    import numpy as np
    from sklearn import preprocessing
    from sklearn.preprocessing import LabelEncoder
    from sklearn.model_selection import train_test_split
    # Normalizing all the features    
    norma_X_new = preprocessing.normalize(X_new)

    # OR
    # Standardizing all the features 
    # standardized_X_new = preprocessing.scale(X_new)

    np.set_printoptions(precision=3)

    # df = ids.sample(frac=1) # randomly shuffling the dataset to ensure uniformity
    # after normalizing, we'll split the dataset

    # splitting the data in 80:20 train:test ratio
    xTrain, xTest, yTrain, yTest = train_test_split(norma_X_new, y, test_size = 0.2, random_state = 0)

    # covnvert arrays into dataframes
    xtrain = pd.DataFrame(xTrain)
    xtest = pd.DataFrame(xTest)
    ytrain = pd.DataFrame(yTrain)
    ytest = pd.DataFrame(yTest)
     
    return xtrain, xtest, ytrain, ytest


xTrainn, xTestt, yTrainn, yTestt = preprocessing(X_new, y)
