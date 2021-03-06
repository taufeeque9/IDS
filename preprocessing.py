import pandas as pd
import numpy as np
from glob import glob
from sklearn import preprocessing
from sklearn.model_selection import StratifiedShuffleSplit
from sklearn.preprocessing import StandardScaler
import os


def combine_csv():
    data_files = sorted(glob('Dataset/*.pcap_ISCX.csv'))
    ids = pd.read_csv(data_files[0])
    for i in range(1, len(data_files)):
        dfi = pd.read_csv(data_files[i])
        dfi.dropna(axis=0, how='any', inplace=True)
        ids = pd.concat((ids, dfi), ignore_index=True)

    del dfi
    print(ids.head())
    print(ids.head())
    ids.to_csv('Dataset/combined_data.csv', index=False)


def get_full_dataset():
    if not os.path.isfile('Dataset/processed_dataset.csv'):
        ids = pd.read_csv('./Dataset/combined_data.csv',
                          dtype={'Flow Bytes/s': str, ' Flow Packets/s': str})
        ids = ids.sample(frac=1, random_state=42)
        ids['Flow Bytes/s'] = ids['Flow Bytes/s'].str.strip()
        ids[' Flow Packets/s'] = ids[' Flow Packets/s'].str.strip()
        ids = ids.astype({'Flow Bytes/s': float, ' Flow Packets/s': float})
        ids.columns = ids.columns.str.strip()
        ids.dropna(inplace=True)
        indices_to_keep = ~ids.isin([np.nan, np.inf, -np.inf]).any(axis=1)
        ids = ids[indices_to_keep]
        ids.reset_index(drop=True, inplace=True)
        ids.to_csv('Dataset/processed_dataset.csv', index=False)
    else:
        ids = pd.read_csv('./Dataset/processed_dataset.csv')

    return ids


def resize_dataset():
    ids = pd.read_csv('./Dataset/combined_data.csv',
                      dtype={'Flow Bytes/s': str, ' Flow Packets/s': str})
    labels_to_drop = {'BENIGN': 0.1, 'DoS Hulk': 0.3, 'DDoS': 0.3, 'PortScan': 0.3}
    for label in labels_to_drop:
        df = ids.loc[ids[' Label'] == label]
        ids.drop(ids.index[ids[' Label'] == label], inplace=True)
        df = df.sample(frac=labels_to_drop[label])
        ids = pd.concat((ids, df), ignore_index=True)

    ids = ids.sample(frac=1, random_state=42)
    ids.reset_index(drop=True, inplace=True)
    ids['Flow Bytes/s'] = ids['Flow Bytes/s'].str.strip()
    ids[' Flow Packets/s'] = ids[' Flow Packets/s'].str.strip()
    ids = ids.astype({'Flow Bytes/s': float, ' Flow Packets/s': float})
    ids.columns = ids.columns.str.strip()
    ids.dropna(inplace=True)
    indices_to_keep = ~ids.isin([np.nan, np.inf, -np.inf]).any(axis=1)
    ids = ids[indices_to_keep]
    ids.to_csv('Dataset/resized_data.csv', index=False)
    return ids


def binary_label_encoder(y):
    '''
    converts multiclass labels to binary labels
    '''
    y["BinaryLabel"] = (y["Label"] != 'BENIGN').astype(int)

    return y


def split_dataset(df):
    '''
    Takes a dataframe df and splits it in 0.7:0.15:0.15 ratio for training, cross-validation and test sets.
    '''

    split1 = StratifiedShuffleSplit(n_splits=1, test_size=0.1, random_state=42)
    for train_index, test0_index in split1.split(df, df['BinaryLabel']):
        train = df.loc[train_index]
        test0 = df.loc[test0_index]

    train.reset_index(drop=True, inplace=True)
    test0.reset_index(drop=True, inplace=True)
    split2 = StratifiedShuffleSplit(n_splits=1, test_size=0.5, random_state=42)
    for test_index, cv_index in split2.split(test0, test0['BinaryLabel']):
        test = test0.loc[test_index]
        cv = test0.loc[cv_index]

    test.reset_index(drop=True, inplace=True)
    cv.reset_index(drop=True, inplace=True)
    return train, cv, test


def main():
    if not os.path.isfile('Dataset/combined_data.csv'):
        combine_csv()
    if not os.path.isfile('Dataset/resized_data.csv'):
        resize_dataset()


if __name__ == "__main__":
    main()
