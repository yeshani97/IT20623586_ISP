import argparse
from stat import filemode
import tensorflow as tf
from keras.models import load_model
import numpy as np
import cv2
import logging
import sys
import time

# setup logging
logging.basicConfig(filename='SQLi_vulnerability.log',filemode='w', level=logging.INFO)

# load the trained model
model = load_model('sqli.h5')

# function to convert a sentence to ASCII as in your training script
# Convert to ASCII

def convert_to_ascii(sentence):
    sentence_ascii=[]

    for i in sentence:
        
        
        """Some characters have values very big e.d 8221 adn some are chinese letters
        I am removing letters having values greater than 8222 and for rest greater 
        than 128 and smaller than 8222 assigning them values so they can easily be normalized"""
       
        if(ord(i)<8222):      # ” has ASCII of 8221
            
            if(ord(i)==8217): # ’  :  8217
                sentence_ascii.append(134)
            
            
            if(ord(i)==8221): # ”  :  8221
                sentence_ascii.append(129)
                
            if(ord(i)==8220): # “  :  8220
                sentence_ascii.append(130)
                
                
            if(ord(i)==8216): # ‘  :  8216
                sentence_ascii.append(131)
                
            if(ord(i)==8217): # ’  :  8217
                sentence_ascii.append(132)
            
            if(ord(i)==8211): # –  :  8211
                sentence_ascii.append(133)
                
                
            """
            If values less than 128 store them else discard them
            """
            if (ord(i)<=128):
                    sentence_ascii.append(ord(i))
    
            else:
                    pass
            

    zer=np.zeros((10000))

    for i in range(len(sentence_ascii)):
        zer[i]=sentence_ascii[i]

    zer.shape=(100, 100)


#     plt.plot(image)
#     plt.show()
    return zer

# function to predict vulnerability
def predict_vulnerability(code):
    image = convert_to_ascii(code)
    x = np.asarray(image,dtype='float')
    image =  cv2.resize(x, dsize=(100,100), interpolation=cv2.INTER_CUBIC)
    image /= 128
    image = image.reshape(1, 100, 100, 1)
    prediction = model.predict(image)
    return prediction[0][0] > 0.7  # returns True if vulnerable, False otherwise

# set up command-line argument parsing
parser = argparse.ArgumentParser(description='Check Python code for vulnerabilities.')
parser.add_argument('filename', type=str, help='The Python file to check')

args = parser.parse_args()

# read the file and check each line for vulnerabilities
print("!!!! Scanning for the SQL injection vulnerabilities !!!!")
with open(args.filename, 'r') as f:
    lines = f.readlines()
    for i, line in enumerate(lines):
        time.sleep(0.1)
        if predict_vulnerability(line):
            log_message = f'[Possible vulnerability detected on line {i+1}:'
            print(f'\033[1;31mPossible vulnerability detected on line {i+1}:\033[0;0m')  # Print line number in color in console
            print(line)
            logging.info('Possible vulnerability detected on line : ' + "\n" + line)  # Log the line number and code to file

print("\nScanning completed.")
print("\nThe output is saved in the log file !!!.")