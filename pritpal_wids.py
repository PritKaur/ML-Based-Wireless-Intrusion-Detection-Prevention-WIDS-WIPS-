import numpy as np # NumPy handles numbers and random data
import pandas as pd # pandas is there so a table can be made
import matplotlib # the plotting library 
matplotlib.use("Agg") # tells matplotlib to draw to image files instead of opening a window
import matplotlib.pyplot as plt # these are the plotting functions you can actually call
from sklearn.model_selection import train_test_split # this is a helper that splits data into training and testing parts
from sklearn.preprocessing import StandardScaler # this rescales features so that they are comparable
from sklearn.neighbors import KNeighborsClassifier # this is the kNN (K-Nearest Neighbors) machine learning model
from sklearn.metrics import accuracy_score, confusion_matrix, classification_report, ConfusionMatrixDisplay # these are tools that measure how well the model did

np.random.seed(42) #The same random data is used every run
n = 600 # the number of rows created per class

# Normal traffic where there is a low deauth count and its mostly data frames
normal = pd.DataFrame({ # this builds a table of normal traffic
    "deauth_count": np.abs(np.random.normal(5, 4, n)),
    "mgmt_ratio": np.clip(np.random.normal(0.35, 0.2, n), 0, 1),
    "frame_len": np.random.normal(180, 70, n),
    "rssi": np.random.normal(-60, 9, n),
    "label": 0 # label 0 means "normal"
})

# Attack traffic where there are more deauth and management frames that are shorter and there's a stronger signal
attack = pd.DataFrame({ # this builds a table of traffic that's not normal
    "deauth_count": np.abs(np.random.normal(14, 9, n)),
    "mgmt_ratio": np.clip(np.random.normal(0.6, 0.2, n), 0, 1),
    "frame_len": np.random.normal(115, 65, n),
    "rssi": np.random.normal(-54, 9, n),
    "label": 1 # label 1 means "attack"
})

data = pd.concat([normal, attack], ignore_index=True) # this stacks the two tables into 1 with 1200 rows

X = data[["deauth_count", "mgmt_ratio", "frame_len", "rssi"]] # these are the inputs that the machine learning model learns from the features
y = data["label"] # this is the answers the model learns to predict 

# this shuffles and splits the data so that 80% is used for training and 20% for testing
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42)

scaler = StandardScaler() # this creates the scaler which basically converts every feature to mean 0 and spread 1
X_train = scaler.fit_transform(X_train) # fit basically learns every column's mean and spread from the training data 
X_test = scaler.transform(X_test) # the same scaling is applied to the test data without learning anything new from that data 

knn = KNeighborsClassifier(n_neighbors=5) # this creates the model such that for any new point, it looks at the  5 closest training points 
knn.fit(X_train, y_train) # training data is being stored so that it can be looked up later

y_pred = knn.predict(X_test) # predicts a label for every test row
acc = accuracy_score(y_test, y_pred) # compares the predictions with the true labels and returns the fraction that were actually correct 

print("Accuracy on synthetic test data: {:.2f}%".format(acc * 100)) # this shows the accuracy as a percentage
cm = confusion_matrix(y_test, y_pred) # this builds a 2x2 table where the rows are the true class and columns are the predicted class
print("\nConfusion Matrix:") # just adds a blank line
print(cm) # prints the table as numbers 

ConfusionMatrixDisplay(cm, display_labels=["Normal", "Deauth Attack"]).plot(cmap="Blues") # this draws the matrix as a coloured grid
plt.title("KNN Confusion Matrix (synthetic data)") 
plt.savefig("confusion_matrix.png", dpi=200, bbox_inches="tight") # saves the figure as an image
print("Confusion matrix saved as confusion_matrix.png") 
print("\nClassification Report:")
print(classification_report(y_test, y_pred, target_names=["Normal", "Deauth Attack"]))

blocked = set() # this is an empty set holding the MACs that are already blocked 

def wips_alert(mac): # this function runs whenever an attack is detected 
    print("[ALERT] Possible deauth attack from", mac) # prints a warning 
    if mac not in blocked: # only continues if the MAC hasn't been blocked yet 
        blocked.add(mac) # remembers the MAC as blocked 
        with open("blocklist.txt", "a") as f:
            f.write(mac + "\n")
        print("[BLOCKED] " + mac + " added to blocklist.txt\n")

# Sample data that is used as test cases 
samples = [
    ["74:DA:38:AA:11:02", 2, 0.2, 230, -61],
    ["00:C0:CA:99:88:77", 30, 0.9, 50, -45],
    ["A4:C3:F0:44:55:66", 6, 0.4, 150, -58],
]

for s in samples: # loops over every test case 
    mac = s[0] # takes the MAC address 
    features = pd.DataFrame([s[1:]], columns=X.columns) 
    features = scaler.transform(features)
    result = knn.predict(features)[0]

    if result == 1: # 1 means attack
        wips_alert(mac) # runs the alert and the block function
    else: # if its normal traffic 
        print("[OK] Traffic from", mac, "looks normal.")