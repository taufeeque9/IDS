import multiprocessing as mp
import sniffer
import time
import pickle
import threading
import numpy as np
from copy import deepcopy
from keras.models import load_model


model = load_model("model.h5")  #assuming keras nn. Can change this if some other kind of model is used.

bad_flows = []

threads = []
lock = threading.Lock()   #This lock is local to the parent process. It won't affect the sniffer process

def detect_intrusion(flow):
    flow.find_features()
    features = (np.array(flow.features)).reshape((1, len(flow.features)))
    chances = (model.predict_proba(features))[0, 0]

    if chances > 0.5:   #can change this threshold to a different value
        print("Possible intrusion detected with a probability of " + str(chances *100) + '%')
        print("Flow parameters:")
        print("Hosts and ports :", flow.identity, "Flow timestamp:", flow.timestamp, "Flow Duration:", flow.flow_duration)
        
        lock.acquire()
        for i in range(len(bad_flows)):  #update bad flows with latest data
            if bad_flows[i].flow_id == flow.flow_id:
                bad_flows[i] = flow

        else:
            bad_flows.append(flow)

        lock.release()


def main():
    queue = mp.Queue()

    sniffer_process = mp.Process(target = sniffer.Sniffer, args = (queue,), daemon= True)
    sniffer_process.start()
    try:
        while 1:
            flow = queue.get()
            flow = deepcopy(flow)   #analyze the flow at the state at the time it was recieved

            thread = threading.Thread(target = detect_intrusion, args = (flow,), daemon = True)
            thread.start()
            threads.append(thread)

    except KeyboardInterrupt:
        sniffer_process.join()   #wait for the sniffer process to end

        while not queue.empty():
            flow = queue.get()
            flow = deepcopy(flow) 

            thread = threading.Thread(target = detect_intrusion, args = (flow,), daemon = True)
            thread.start()
            threads.append(thread)

        queue.close()

        for Thread in threads:
            Thread.join()

        bad_flows = bad_flows[::-1]  #latest bad flow first

        try:
            file = open('bad_flows', 'rb')
            old_bad_flows = pickle.load(file)
            file.close()

            bad_flows = bad_flows + old_bad_flows

        except:  #file doesn't exist
            pass

        file = open('bad_flows', 'wb')
        pickle.dump(bad_flows, file)
        file.close()


if __name__ == '__main':
    main()