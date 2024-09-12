from PIL import Image  # Import the Python Imaging Library (PIL) to handle image operations
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import getpass

class Steganography:
    def __init__(self):
        pass

    def encode_image(self, image_path, output_path, message):
        # Open the image file
        image_path = image_path = "/Users/benfrost/Desktop/anna.PNG"
        image = Image.open(image_path)
        im = image.convert("RGB")

        # Convert the message into a binary string
        binary_message = "".join(format(ord(char), "08b") for char in message)
        # Append a delimiter to mark the end of the message
        binary_message += "111111111111"  # Delimiter to signify the end of the message

        pixels = list(im.getdata())  # Get all the pixels from the image
        data_index = 0  # Track the current index of the message being encoded
        new_pixels = []  # This will store the new modified pixel values

        # Iterate over each pixel in the image
        for pixel in pixels:
            r, g, b = pixel  # Get the RGB values of the pixel
            new_pixel = list(pixel)  # Convert the pixel tuple to a list for modification

            for i in range(3):  # Loop over R, G, B channels
                if data_index < len(binary_message):  # If there's still data left to encode
                    # Replace the least significant bit (LSB) with a bit from the message
                    new_pixel[i] = new_pixel[i] & ~1 | int(binary_message[data_index])
                    data_index += 1

            new_pixels.append(tuple(new_pixel))  # Add the modified pixel back

        # Check if the message fits into the image
        if data_index < len(binary_message):
            raise ValueError("Message is too long to fit in the image.")

        # Create a new image with the modified pixels
        im.putdata(new_pixels)
        im.save(output_path)
        print(f"Message encoded and saved to {output_path}")






    def decode_image(self, image_path):
        img = Image.open(image_path)
        img = img.convert("RGB")
        
        binary_message = ''  # This will hold the extracted binary message
        pixels = list(img.getdata())  # Get the pixel data as a list

        # Extract the least significant bit (LSB) from each pixel's RGB values
        for pixel in pixels:
            for i in range(3):  # R, G, B values
                binary_message += str(pixel[i] & 1) # extract the lsb in the binary of the colours found and perform a bitwise operation

        # Look for the delimiter to identify the end of the message
        delimiter = "111111111111"  # Same delimiter used in encoding
        delimiter_index = binary_message.find(delimiter) # find the pre set delimitter in the binary message

        if delimiter_index != -1:
            binary_message = binary_message[:delimiter_index]  # Truncate the message at the delimiter
        else:
            print("Delimiter not found, possible corruption.")
            return None

        # Rebuild the message from the binary string
        bytes_data = [binary_message[i:i+8] for i in range(0, len(binary_message), 8)]
        decoded_message = ''.join([chr(int(byte, 2)) for byte in bytes_data])

        print(f"Decoded message: {decoded_message}")
        return decoded_message

    
    
    
    def encrypt_message(self, message, key):
        cipher = AES.new(key, AES.MODE_CBC)#Retrieves the Initialization Vector
                                            #from the cipher object. In CBC mode, the IV is used to 
                                            # randomize the encryption process and ensure that the same plaintext 
                                            # results in different ciphertext each time

        iv = cipher.iv # randomizes the plaintext so the same text isnt the same in the cipher
        encrypted_message = cipher.encrypt(pad(message.encode(), AES.block_size)) # message encode convert plaintext to bytes,
                                                                                  # pad and block size bit, pads the message so its
                                                                                  # the correct size for aes, 16 block length.
                                                                                  # encrypt does what ot says, using the AES and block size
                                                                                  
        return iv + encrypted_message  # Return IV concatenated with the encrypted message
        
    



    def decrypt_message(self, encrypted_message, key):
        iv = encrypted_message[:16]  # First 16 bytes are the IV
        cipher = AES.new(key, AES.MODE_CBC, iv) 
        decrypted_message = unpad(cipher.decrypt(encrypted_message[16:]), AES.block_size)  
        return decrypted_message.decode()


    def example(self):
        # Example usage
        key = get_random_bytes(16)
        image_path = "input_image.png"
        output_path = "/Users/benfrost/Desktop/output_image.png"
        message = getpass.getpass("enter message here:").strip()

        # Encode the message into the image
        encrypted_message = self.encrypt_message(message, key)
        print(f"Encrypted message: {encrypted_message}")

        # Encode the encrypted message into the image
        encrypted_message_str = ''.join(chr(byte) for byte in encrypted_message)  # Convert bytes to a string for steganography
        self.encode_image(image_path, output_path, encrypted_message_str)

        # Decode the hidden message from the output image
        decoded_encrypted_message_str = self.decode_image(output_path)
        decoded_encrypted_message = decoded_encrypted_message_str.encode('latin1')  # Convert string back to bytes

        # Decrypt the message
        decrypted_message = self.decrypt_message(decoded_encrypted_message, key)
        print(f"Decoded and decrypted message: {decrypted_message}")

# To use the class
if __name__ == "__main__":
    steg = Steganography()  # Create an instance of the Steganography class
    steg.example()  # Run the example method to encode and decode a message