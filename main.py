from digital_signature import generate_key_pair, sign_file, verify_signature
import os

def main():
    # Tạo file test
    test_file = "test.txt"
    with open(test_file, "w") as f:
        f.write("This is a test file for digital signature.")
    
    print("1. Tạo cặp khóa RSA...")
    private_key, public_key = generate_key_pair()
    print("Đã tạo và lưu cặp khóa vào private_key.pem và public_key.pem")
    
    print("\n2. Ký số file...")
    signature_path = sign_file(test_file)
    print(f"Đã ký số file và lưu chữ ký vào {signature_path}")
    
    print("\n3. Xác thực chữ ký...")
    is_valid = verify_signature(test_file, signature_path)
    if is_valid:
        print("Chữ ký hợp lệ!")
    else:
        print("Chữ ký không hợp lệ!")
    
    # Thử sửa file và xác thực lại
    print("\n4. Thử sửa file và xác thực lại...")
    with open(test_file, "a") as f:
        f.write("Modified content")
    
    is_valid = verify_signature(test_file, signature_path)
    if is_valid:
        print("Chữ ký vẫn hợp lệ!")
    else:
        print("Chữ ký không còn hợp lệ sau khi sửa file!")

if __name__ == "__main__":
    main() 