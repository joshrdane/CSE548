"""
This script automates the machine learning workflow for the CSE 548 Project.

It performs the following steps for three distinct attack scenarios (A, B, C):
1.  Filters the NSL-KDD dataset to create scenario-specific training and testing sets.
2.  Exports the filtered datasets to CSV files.
3.  Pre-processes the data (one-hot encoding for categorical features, scaling).
4.  Builds, trains, and evaluates a Feed-Forward Neural Network (FNN).
5.  Saves a detailed report, confusion matrix, and plots for accuracy and loss.
"""

# Standard library imports
import os
import sys
from contextlib import redirect_stdout

# Third-party imports
import matplotlib.pyplot as plt
import numpy
import pandas
from keras.layers import Dense
from keras.models import Sequential
from sklearn.compose import ColumnTransformer
from sklearn.metrics import confusion_matrix
from sklearn.preprocessing import OneHotEncoder, StandardScaler

# --- CONFIGURATION CONSTANTS ---

# File paths for the NSL-KDD dataset
# Per project requirements, the full training dataset is used.
TRAIN_PATH = "NSL-KDD/KDDTrain+.txt"
TEST_PATH = "NSL-KDD/KDDTest+.txt"

# FNN model training parameters
BATCH_SIZE = 10
NUM_EPOCH = 10

# Definition of the four major attack classes and their subclasses
ATTACK_CLASSES = {
    "DoS": ['apache2', 'back', 'land', 'neptune', 'mailbomb', 'pod', 'processtable', 'smurf', 'teardrop', 'udpstorm', 'worm'],
    "Probe": ['ipsweep', 'mscan', 'portsweep', 'saint', 'satan', 'nmap'],
    "U2R": ['buffer_overflow', 'loadmodule', 'perl', 'ps', 'rootkit', 'sqlattack', 'xterm'],
    "R2L": ['ftp_write', 'guess_passwd', 'httptunnel', 'imap', 'multihop', 'named', 'phf', 'sendmail', 'snmpgetattack', 'spy', 'snmpguess', 'warezclient', 'warezmaster', 'xlock', 'xsnoop']
}

# Definition of the three scenarios for training and testing
# Keys match the main attack classes defined above.
# The integer values correspond to the order in ATTACK_CLASSES (1=DoS, 2=Probe, etc.)
SCENARIOS = {
    'A': {'train': [1, 3], 'test': [2, 4]},
    'B': {'train': [1, 2], 'test': [1]},
    'C': {'train': [1, 2], 'test': [1, 2, 3]}
}


def run_scenario(scenario_name, scenario_data, train_df_raw, test_df_raw):
    """
    Executes the full ML workflow for a single scenario.
    """
    # --- 1. Setup Results Directory ---
    dir_name = os.path.join("scenarios", scenario_name)
    os.makedirs(dir_name, exist_ok=True)
    results_filepath = os.path.join(dir_name, "report.txt")

    print(f"--- Running Scenario: {scenario_name}. Saving results to '{dir_name}' folder ---")

    # Redirect all subsequent print() outputs to the scenario's report file
    with open(results_filepath, 'w') as f:
        with redirect_stdout(f):
            print(f"--- Scenario: {scenario_name} Report ---")

            # --- 2. Filter Data Based on Scenario ---
            attack_keys = list(ATTACK_CLASSES.keys())
            train_attacks = [subclass for index in scenario_data['train'] for subclass in ATTACK_CLASSES[attack_keys[index - 1]]]
            test_attacks = [subclass for index in scenario_data['test'] for subclass in ATTACK_CLASSES[attack_keys[index - 1]]]
            train_filter = ['normal'] + train_attacks
            test_filter = ['normal'] + test_attacks

            # The 42nd column (index 41) contains the attack label string
            train_df_filtered = train_df_raw[train_df_raw.iloc[:, 41].isin(train_filter)]
            test_df_filtered = test_df_raw[test_df_raw.iloc[:, 41].isin(test_filter)]

            print(f"\nTraining set created with {len(train_df_filtered)} records.")
            print(f"Testing set created with {len(test_df_filtered)} records.")

            # --- 3. Export Filtered Data to CSV ---
            # Use header=False and index=False to match the original dataset format
            train_df_filtered.to_csv(os.path.join(dir_name, 'train.csv'), header=False, index=False)
            test_df_filtered.to_csv(os.path.join(dir_name, 'test.csv'), header=False, index=False)
            print("Exported scenario-specific train.csv and test.csv files.")
            print()

            # --- 4. Prepare Data for Model ---
            # Features are in the first 41 columns (0-40)
            X_train = train_df_filtered.iloc[:, 0:41].values
            y_train_labels = train_df_filtered.iloc[:, 41].values
            X_test = test_df_filtered.iloc[:, 0:41].values
            y_test_labels = test_df_filtered.iloc[:, 41].values

            # Convert string labels to binary (0 for 'normal', 1 for any attack)
            y_train = numpy.array([0 if label == 'normal' else 1 for label in y_train_labels])
            y_test = numpy.array([0 if label == 'normal' else 1 for label in y_test_labels])

            # --- 5. Pre-process Features ---
            # One-hot encode the three categorical features at indices 1, 2, and 3
            # handle_unknown='ignore' prevents errors if the test set has categories not seen in training
            ct = ColumnTransformer(
                [('one_hot_encoder', OneHotEncoder(handle_unknown='ignore'), [1, 2, 3])],
                remainder='passthrough'
            )
            X_train_encoded = ct.fit_transform(X_train)
            X_test_encoded = ct.transform(X_test)

            # Scale numerical features. 'with_mean=False' is required for sparse matrices from the encoder.
            sc = StandardScaler(with_mean=False)
            X_train_processed = sc.fit_transform(X_train_encoded)
            X_test_processed = sc.transform(X_test_encoded)

            # --- 6. Build and Train the FNN Model ---
            classifier = Sequential([
                Dense(units=6, kernel_initializer='uniform', activation='relu', input_dim=X_train_processed.shape[1]),
                Dense(units=6, kernel_initializer='uniform', activation='relu'),
                Dense(units=1, kernel_initializer='uniform', activation='sigmoid')
            ])
            classifier.compile(optimizer='adam', loss='binary_crossentropy', metrics=['accuracy'])

            print("--- Training Progress ---")
            # Use verbose=2 for clean, one-line-per-epoch logging suitable for files
            history = classifier.fit(X_train_processed, y_train, batch_size=BATCH_SIZE, epochs=NUM_EPOCH, verbose=2)

            # --- 7. Evaluate the Model ---
            loss, accuracy = classifier.evaluate(X_train_processed, y_train, verbose=0)
            print(f"\n\n--- Training Evaluation ---")
            print(f"Loss: {loss:.4f}, Accuracy: {accuracy:.4f}")

            loss_test, accuracy_test = classifier.evaluate(X_test_processed, y_test, verbose=0)
            print(f"\n--- Testing Evaluation ---")
            print(f"Loss: {loss_test:.4f}, Accuracy: {accuracy_test:.4f}")

            # Get predictions and apply a 0.9 threshold to classify as attack (1) or normal (0)
            y_pred = (classifier.predict(X_test_processed, verbose=0) > 0.9)
            cm = confusion_matrix(y_test, y_pred)
            print(f"\n--- Confusion Matrix (TN, FP, FN, TP) ---")
            print(cm)

            # --- 8. Save Visualization Plots ---
            for metric in ['accuracy', 'loss']:
                plt.figure()
                plt.plot(history.history[metric])
                plt.title(f'Model {metric.capitalize()} - Scenario {scenario_name}')
                plt.ylabel(metric.capitalize())
                plt.xlabel('Epoch')
                plt.legend(['train'], loc='upper left')
                plt.savefig(os.path.join(dir_name, f'{metric}.png'))
                plt.close()

        print(f"\nSaved all output files to '{dir_name}' folder.")


def main():
    """
    Main function to load data and orchestrate the scenario runs.
    """
    print("Loading raw NSL-KDD dataset files...")
    try:
        train_df_raw = pandas.read_csv(TRAIN_PATH, header=None, encoding="ISO-8859-1")
        test_df_raw = pandas.read_csv(TEST_PATH, header=None, encoding="ISO-8859-1")
        print("Loading Completed.\n")
    except FileNotFoundError as e:
        print(f"Error: {e}. Make sure the NSL-KDD dataset is in the correct path.")
        sys.exit(1)

    # Run the workflow for each defined scenario
    for name, data in SCENARIOS.items():
        run_scenario(name, data, train_df_raw, test_df_raw)

    print("\nAll scenarios processed successfully.")


if __name__ == "__main__":
    main()
