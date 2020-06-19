import threading
import sniffer
import time
import numpy as np
from copy import deepcopy
import pickle

from keras.models import load_model

model = load_model("model.h5")  #assuming keras nn. Can change this if some other kind of model is used.

checked_flows = set()

bad_flows = []

def detect_intrusion():
    FLOWS = deepcopy(sniffer.FLOWS)

    for identity in FLOWS:
        for flow in FLOWS[identity]:

            if flow.flow_id in checked_flows:
                continue

            if flow.num_packets < 5:   #Insignificant and probably a result of erroneous connction termination
                continue

            flow.find_features()
            features = (np.array(flow.features)).reshape((1, len(flow.features)))
            chances = (model.predict_proba(features))[0, 0]
            
            if chances > 0.5:   #can change this threshold to a different value
                print("Possible intrusion detected with a probability of " + str(chances *100) + '%')
                print("Flow parameters:")
                print("Hosts and ports :", identity, "Flow timestamp:", flow.timestamp, "Flow Duration:", flow.flow_duration)
                bad_flows.append(flow)

            if not flow.state:   #flow is closed
                checked_flows.add(flow.flow_id)

sniffer_thread = threading.Thread(target = sniffer.Sniffer)

try:
    sniffer_thread.start()

    while 1:
        sniffer_thread.join(120)  #check after every 2 mins. Can issue KeyboardInterrupt in this period.

        detection_thread = threading.Thread(target= detect_intrusion)
        detection_thread.start()
        detection_thread.join()

except KeyboardInterrupt:
    sniffer_thread.alive = False
    sniffer_thread.join()

    detect_intrusion()

    bad_flows = bad_flows[::-1]  #latest bad flow first

    try:
        file = open('bad_flows', 'rb')
        old_bad_flows = pickle.load(file)
        file.close()

        bad_flows = bad_flows + old_bad_flows

    except:
        pass

    file = open('bad_flows', 'wb')
    pickle.dump(bad_flows, file)
    file.close()