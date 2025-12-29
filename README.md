# Secure File Transfer System (Hệ thống Truyền tin An toàn)

Ứng dụng truyền tải tệp tin (File Transfer) an toàn giữa Client (Sender) và Server (Receiver) sử dụng giao thức TCP/IP. Hệ thống đảm bảo tính bảo mật (Confidentiality), tính toàn vẹn (Integrity) và tính chống chối bỏ (Non-repudiation) thông qua việc áp dụng các kỹ thuật mã hóa hiện đại.

## 📋 Mục lục

1. [Giới thiệu](https://www.google.com/search?q=%23gi%E1%BB%9Bi-thi%E1%BB%87u)
2. [Các tính năng chính](https://www.google.com/search?q=%23c%C3%A1c-t%C3%ADnh-n%C4%83ng-ch%C3%ADnh)
3. [Cơ chế bảo mật](https://www.google.com/search?q=%23c%C6%A1-ch%E1%BA%BF-b%E1%BA%A3o-m%E1%BA%ADt)
4. [Yêu cầu cài đặt](https://www.google.com/search?q=%23y%C3%AAu-c%E1%BA%A7u-c%C3%A0i-%C4%91%E1%BA%B7t)
5. [Hướng dẫn sử dụng](https://www.google.com/search?q=%23h%C6%B0%E1%BB%9Bng-d%E1%BA%ABn-s%E1%BB%AD-d%E1%BB%A5ng)
6. [Cấu trúc dự án](https://www.google.com/search?q=%23c%E1%BA%A5u-tr%C3%BAc-d%E1%BB%B1-%C3%A1n)

---

## 📖 Giới thiệu

Dự án này xây dựng một ứng dụng Desktop với giao diện đồ họa (GUI) cho phép người dùng gửi tệp tin qua mạng LAN hoặc Localhost một cách an toàn. Ứng dụng tự động xử lý việc tạo khóa, bắt tay (handshake), chia nhỏ tệp tin, mã hóa và xác thực dữ liệu.

## ✨ Các tính năng chính

* **Giao diện đồ họa (GUI):** Dễ sử dụng, được xây dựng bằng `tkinter`.
* **Mô hình Client-Server:** Sử dụng Python Socket (TCP).
* **Truyền tệp đa luồng:** Giao diện không bị treo khi đang gửi/nhận file nhờ `threading`.
* **Chia nhỏ tệp tin:** Tệp tin được chia thành các phần nhỏ để mã hóa và truyền tải.
* **Nhật ký hoạt động (Logs):** Hiển thị trạng thái kết nối và quá trình truyền file trực tiếp trên giao diện.

## 🔒 Cơ chế bảo mật

Hệ thống sử dụng thư viện `pycryptodome` để thực hiện các kỹ thuật sau:

1. **Mã hóa lai (Hybrid Encryption):**
* **Mã hóa đối xứng (Symmetric):** Dữ liệu tệp tin được mã hóa bằng thuật toán **3DES (Triple DES)** chế độ CBC với Session Key ngẫu nhiên (24 bytes).
* **Mã hóa bất đối xứng (Asymmetric):** Session Key được mã hóa bằng thuật toán **RSA (2048 bit)** sử dụng khóa công khai của người nhận.


2. **Toàn vẹn dữ liệu & Chữ ký số (Integrity & Digital Signature):**
* Sử dụng hàm băm **SHA-512** để tạo mã băm cho dữ liệu và Metadata.
* Sử dụng **RSA Digital Signature (PKCS#1 v1.5)** để ký lên mã băm, đảm bảo người gửi là xác thực và dữ liệu không bị chỉnh sửa trên đường truyền.



## ⚙️ Yêu cầu cài đặt

Bạn cần cài đặt Python 3.x và thư viện mã hóa `pycryptodome`.

1. **Cài đặt Python:** [Tải tại python.org](https://www.python.org/)
2. **Cài đặt thư viện phụ thuộc:**
Mở terminal hoặc command prompt và chạy lệnh:
```bash
pip install pycryptodome

```


*(Lưu ý: Với Windows, nếu gặp lỗi, hãy thử `pip install pycryptodomex`)*

## 🚀 Hướng dẫn sử dụng

### Bước 1: Chuẩn bị Khóa (Lần chạy đầu tiên)

Hệ thống sẽ tự động sinh cặp khóa RSA (`private_key.pem` và `public_key.pem`) nếu chưa tồn tại.

* **Lưu ý quan trọng:** Để mô phỏng truyền tin thực tế, bên Gửi cần có **Public Key của bên Nhận** và ngược lại.
* Copy `receiver_public_key.pem` (từ thư mục bên Nhận) sang thư mục bên Gửi.
* Copy `sender_public_key.pem` (từ thư mục bên Gửi) sang thư mục bên Nhận.
* *Nếu chạy trên cùng một máy (Localhost) và cùng thư mục, bước này có thể bỏ qua.*



### Bước 2: Khởi chạy Receiver (Người nhận)

1. Chạy file `receiver_app.py`:
```bash
python receiver_app.py

```


2. Nhập **Port** (mặc định 12345).
3. Chọn thư mục lưu file nhận được (**Output Directory**).
4. Nhấn nút **"Start Server"**.

### Bước 3: Khởi chạy Sender (Người gửi)

1. Chạy file `sender_app.py`:
```bash
python sender_app.py

```


2. Nhập **IP Receiver** (nếu chạy trên cùng máy thì để `127.0.0.1`).
3. Nhập **Port** (phải trùng với Port bên Receiver).
4. Chọn file cần gửi bằng nút **"Browse"**.
5. Nhấn nút **"Send File"**.

### Bước 4: Kiểm tra kết quả

* Quan sát khung Log trên cả hai ứng dụng để xem quá trình bắt tay, gửi metadata và từng phần của file.
* Khi hoàn tất, Receiver sẽ hiện thông báo "File received and verified successfully!".
* Kiểm tra file trong thư mục Output để đảm bảo file mở được và nội dung không bị lỗi.


1. Tạo file `requirements.txt` để nộp kèm dự án.
2. Giải thích sâu hơn về lý do tại sao dùng `DES3` thay vì `AES` trong code này (để bạn trả lời vấn đáp nếu giảng viên hỏi).
3. Vẽ biểu đồ luồng (Flowchart) mô tả quá trình trao đổi khóa và truyền tin.
