'''
Referencing:

This code is written with reference belows links:
>URL Reference:
    URL Reference:
    > https://daniellerch.me/stego/intro/lsb-en/
    > https://www.geeksforgeeks.org/image-based-steganography-using-python/
    > https://youtu.be/JeV-WKK1A9Y?si=C4qz_8KPQzJIOlDc

    How its used:
    > The idea behind least significant bit (LSB) stenography is utilized. This code uses a technique that alters the least significant bit of the red channel in an image to hide a message. The message is converted to binary and embedded in the image by modifying the red channel of the pixels. The code reads an image file from the input folder, embeds the message in the image, and saves the new image with the hidden message in the output folder.
    > The process of implementing image stenography in Python is outlined. Specifically, it utilizes the OpenCV library for loading, manipulating, and saving images. The code reads an image file from the input folder, embeds the message in the image, and saves the new image with the hidden message in the output folder.
    > In this YouTube video, discover how to utilize NumPy for effective bit manipulation. The code demonstrates how we leverage NumPy's array capabilities to seamlessly embed message bits into the pixels of an image.

'''

# Importing the required libraries
# Need to install opencv-python the command is below
# pip install opencv-python
import cv2
import numpy as np
import os

# Making paths working on all OS
BASE = os.path.dirname(os.path.abspath(__file__))

# Message to be hidden in the image
MSG = "Security in Computing COSC2560"
# Calculate message bit length (1 character = 8 bits)
PIXEL_LENGTH = len(MSG) * 8

# Modify the pixel array to embed the message in the image
# using the least significant bit (LSB) method
def mod_pixel(bin_array, pixel_array):
    # Get the red channel of the pixel array
    r_channel = pixel_array[:, 0]
    # Create masks to determine even and odd red channels
    even_mask = (r_channel % 2 == 0)
    # Invert the even mask to get the odd mask
    odd_mask = ~even_mask

    # Create masks for 0s and 1s in the binary array
    bin_0_mask = (bin_array == 0)
    # Invert the 0 mask to get the 1 mask
    bin_1_mask = (bin_array == 1)

    # Ensure the masks have the same shape
    # and get the minimum length of the masks
    min_length = min(len(bin_0_mask), len(odd_mask)) # Get the minimum length of the masks
    bin_0_mask = bin_0_mask[:min_length] # Get the minimum length of the 0 mask
    bin_1_mask = bin_1_mask[:min_length] # Get the minimum length of the 1 mask
    odd_mask = odd_mask[:min_length] # Get the minimum length of the odd mask
    even_mask = even_mask[:min_length] # Get the minimum length of the even mask

    # Change pixel array to embed message
    # Set 0 bits in odd pixels
    pixel_array[:min_length][bin_0_mask & odd_mask, 0] -= 1
    # Set bits of 1 in even-numbered pixels
    pixel_array[:min_length][bin_1_mask & even_mask, 0] += 1

# Set the message to a bit array
bins = np.array([int(bit) for char in MSG for bit in f"{ord(char):08b}"], dtype=np.uint8)

# Load the base image file from the input folder
input_file = os.path.join(BASE, 'input', 'base.jpg')
cover_file = cv2.imread(input_file)

# Get the height and width of the cover image
# and reshape the image to a 2D array
height, width = cover_file.shape[:2]

# Calculate the number of pixels needed for the message
# and flatten the image to a 1D array
# Set the number of pixels needed for the message
# and flatten the image to a 1D array
num_pixels_needed = PIXEL_LENGTH

# Flatten the image and modify only the required number of pixels
# Set the target pixels to embed the message in the image
# Flatten the image and get the target pixels
# to embed the message in the image
# Flatten the image and get the target pixels
# to embed the message in the image
flattened_image = cover_file.reshape(-1)
target_px = flattened_image[:num_pixels_needed]

# Modify the target pixels to embed the message in the image
# using the least significant bit (LSB) method
# Modify the target pixels to embed the message in the image
mod_pixel(bins, target_px.reshape(-1, 1))


# Reshape the modified pixel array to the original image shape
# and save the new image with the hidden message
# Reshape the modified pixel array to the original image shape
# Set the new pixels to the original image shape
# and save the new image with the hidden message
new_pixels = flattened_image.reshape(height, width, 3)

# Save the new image with the hidden message
# in the output folder as 'stego.png'
# Set output file path and save the new image
output_file = os.path.join(BASE, 'output', 'task6_stego.png')
cv2.imwrite(output_file, new_pixels)

# Print the completion message
print("Code Ran Successfully, Please look in the output folder.")
