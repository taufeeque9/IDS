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


# converts the categorical data to numeric data for easier handling eg Destination Port to 1, Flow Duration 2 and so on...
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
    
    return xTrain, xTest, yTrain, yTest

heheh = preprocessing(X_new, y)
print(heheh)

xtrain = pd.DataFrame(xTrain)
xtest = pd.DataFrame(xTest)
ytrain = pd.DataFrame(yTrain)
ytest = pd.DataFrame(yTest)
