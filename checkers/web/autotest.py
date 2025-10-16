#!/usr/bin/env python3
import sys
import requests
import random
import string
import os
import time
import socketio
import shutil
from bs4 import BeautifulSoup
import json

DEFAULT_HOST = "http://localhost:5000"

def normalize_host(host):
    if not host.startswith("http://") and not host.startswith("https://"):
        host = "http://" + host

    if ':' not in host.split("//")[1]:
        host += ":5000"
    return host

def info():
    print("vulns: 1:1")
    return 101

def generate_random_username():
    chars = string.ascii_uppercase + string.digits
    random_id = ''.join(random.choices(chars, k=6))
    return f"test_user_{random_id}"

def generate_random_password():
    uppercase = random.choice(string.ascii_uppercase)
    lowercase = random.choice(string.ascii_lowercase)
    digit = random.choice(string.digits)
    special = random.choice('!@#$%^&*()_+-=[]{}|;:,.<>?')
    other = ''.join(random.choices(string.ascii_letters + string.digits, k=4))
    password = uppercase + lowercase + digit + special + other
    return ''.join(random.sample(password, len(password)))

def get_csrf_token(session, url):
    """Получаем CSRF токен со страницы"""
    try:
        response = session.get(url)
        if response.status_code != 200:
            return None
        
        soup = BeautifulSoup(response.text, 'html.parser')
        csrf_token = soup.find('input', {'name': 'csrf_token'})['value']
        return csrf_token
    except Exception:
        return None

def check_registration_login(host):
    """Тест регистрации и входа в аккаунт"""
    print("\n=== Тест регистрации и входа ===")
    
    session = requests.Session()
    username = generate_random_username()
    password = generate_random_password()
    
    print(f"Генерируем тестового пользователя: {username} / {password}")
    
    try:
        start_time = time.time()
        
        # 1. Получаем CSRF токен для регистрации
        csrf_token = get_csrf_token(session, f"{host}/register")
        if not csrf_token:
            print("Ошибка: не удалось получить CSRF токен для регистрации")
            return False, None, None
        
        # 2. Проверяем доступность username
        check_username_resp = session.get(f"{host}/check_username", 
                                        params={"username": username})
        if check_username_resp.status_code != 200:
            print(f"Ошибка: не удалось проверить username (код {check_username_resp.status_code})")
            return False, None, None
        
        # 3. Регистрируем пользователя
        register_data = {
            "csrf_token": csrf_token,
            "username": username,
            "password": password,
            "confirm_password": password,
            "submit": "Зарегистрироваться"
        }
        
        register_resp = session.post(f"{host}/register", 
                                   data=register_data,
                                   allow_redirects=False)
        
        if register_resp.status_code != 302:
            print(f"Ошибка регистрации (код {register_resp.status_code})")
            print(f"Ответ сервера: {register_resp.text}")
            return False, None, None

        # 4. Проверяем, что username теперь занят
        check_username_resp = session.get(f"{host}/check_username", 
                                        params={"username": username})
        if check_username_resp.json().get("exists") != True:
            print("Ошибка: пользователь не зарегистрирован")
            return False, None, None
        
        # 5. Получаем CSRF токен для входа
        csrf_token = get_csrf_token(session, f"{host}/login")
        if not csrf_token:
            print("Ошибка: не удалось получить CSRF токен для входа")
            return False, None, None
        
        # 6. Вход в систему
        login_data = {
            "csrf_token": csrf_token,
            "username": username,
            "password": password,
            "submit": "Войти"
        }
        
        login_resp = session.post(f"{host}/login", 
                                data=login_data,
                                allow_redirects=False)
        
        if login_resp.status_code != 302:
            print(f"Ошибка входа (код {login_resp.status_code})")
            print(f"Ответ сервера: {login_resp.text}")
            return False, None, None
        
        # 7. Проверяем успешность входа
        account_resp = session.get(f"{host}/account")
        if account_resp.status_code != 200:
            print("Ошибка: не удалось получить доступ к аккаунту")
            return False, None, None
        
        # 8. Проверяем имя пользователя
        if f"{username}" not in account_resp.text:
            print(f"Ошибка: вошли не как {username}")
            return False, None, None
        
        elapsed_time = time.time() - start_time
        print(f"Успех! Пользователь {username} зарегистрирован и вошел в систему. Время: {elapsed_time:.2f} сек")
        return session, username, password
    
    except Exception as e:
        print(f"Ошибка при регистрации/входе: {str(e)}")
        return False, None, None

def test_public_chat(session, host):
    """Тест публичного чата с использованием Socket.IO"""
    print("\n=== Тест публичного чата ===")
    other_code = generate_random_password()
    
    try:
        start_time = time.time()
        
        # 1. Проверка доступа к чату
        chat_resp = session.get(f"{host}/chat")
        if chat_resp.status_code != 200:
            print(f"Ошибка доступа к чату (код {chat_resp.status_code})")
            return False
        
        # 2. Настройка Socket.IO клиента
        sio = socketio.Client(logger=False, engineio_logger=False)
        
        # Обработчик для входящих сообщений
        received_messages = []
        @sio.on('new_message')
        def on_message(data):
            received_messages.append(data['message'])
        
        # Получаем cookies
        cookies = session.cookies.get_dict()
        session_cookie = cookies.get('session')
        if not session_cookie:
            print("Ошибка: не найден session cookie")
            return False
            
        try:
            # Подключаемся с увеличенным таймаутом
            sio.connect(
                host,
                headers={"Cookie": f"session={session_cookie}"},
                transports=['websocket', 'polling'],
            )
            
            # Даем время на установление соединения 
            if not sio.connected:
                print("Ошибка: не удалось подключиться к Socket.IO")
                return False
            
            # 3. Отправка тестового сообщения
            test_message = f"Привет, это тестовое сообщение для проверки работоспособности. Код: {other_code}"
            sio.emit('send_message', {'message': test_message})
            
            # Ждем обработки сообщения
            time.sleep(0.2)
            
            # Проверяем через API и socket.io (HTML)
            chat_resp = session.get(f"{host}/chat")
            if test_message not in chat_resp.text and test_message not in received_messages:
                print(f"Ошибка: сообщение '{test_message}' не найдено ни в HTML, ни в Socket.IO")
                return False
                
            elapsed_time = time.time() - start_time
            print(f"Успех! Сообщение '{test_message}' отправлено в чат. Время: {elapsed_time:.2f} сек")
            return True
            
        finally:
            if sio.connected:
                sio.disconnect()
    
    except Exception as e:
        print(f"Ошибка при тестировании чата: {str(e)}")
        return False

def test_private_chat(session, host, flag=None):
    """Тест приватного чата с отправкой сообщения (или флага, если указано)"""
    print("\n=== Тест приватного чата ===")

    try:
        start_time = time.time()

        # 1. Получаем список чатов до создания
        initial_resp = session.get(f"{host}/my_private_chats")
        if initial_resp.status_code != 200:
            print(f"Ошибка доступа к списку чатов (код {initial_resp.status_code})")
            return False, None

        initial_soup = BeautifulSoup(initial_resp.text, 'html.parser')
        initial_ids = {
            link.get('href').split('/')[-1]
            for link in initial_soup.find_all('a', href=True)
            if link.get('href').startswith('/private_chat/')
        }

        # 2. Получаем CSRF токен
        csrf_token = get_csrf_token(session, f"{host}/create_private_chat")
        if not csrf_token:
            print("Ошибка: не удалось получить CSRF токен для создания чата")
            return False, None

        # 3. Создаём приватный чат
        chat_password = generate_random_password()
        create_data = {
            "csrf_token": csrf_token,
            "password": chat_password,
            "submit": "Создать"
        }

        create_resp = session.post(
            f"{host}/create_private_chat",
            data=create_data,
            allow_redirects=False
        )

        if create_resp.status_code != 302:
            print(f"Ошибка: ожидался редирект 302, получен код {create_resp.status_code}")
            return False, None

        if not create_resp.headers.get('Location', '').endswith('/my_private_chats'):
            print("Ошибка: редирект ведёт не на /my_private_chats")
            return False, None

        # 4. Получаем ID нового чата
        my_chats_resp = session.get(f"{host}/my_private_chats")
        if my_chats_resp.status_code != 200:
            print(f"Ошибка доступа к списку чатов после создания (код {my_chats_resp.status_code})")
            return False, None

        soup = BeautifulSoup(my_chats_resp.text, 'html.parser')
        chat_table = soup.find('table')
        new_chat_ids = set()

        if chat_table:
            for row in chat_table.find_all('tr')[1:]:
                cells = row.find_all('td')
                if cells:
                    chat_id = cells[0].text.strip()
                    if chat_id not in initial_ids:
                        new_chat_ids.add(chat_id)

        if not new_chat_ids:
            print("Ошибка: не найден ID нового чата в списке")
            return False, None

        new_chat_id = new_chat_ids.pop()
        print(f"Создан приватный чат {new_chat_id} с паролем {chat_password}")

        # 5. Подключаемся к чату
        csrf_token = get_csrf_token(session, f"{host}/connect_private_chat")
        if not csrf_token:
            print("Ошибка: не удалось получить CSRF токен для подключения")
            return False, None

        connect_data = {
            "csrf_token": csrf_token,
            "chat_id": new_chat_id,
            "password": chat_password,
            "submit": "Подключиться"
        }

        connect_resp = session.post(
            f"{host}/connect_private_chat",
            data=connect_data,
            allow_redirects=False
        )

        if connect_resp.status_code != 302:
            print(f"Ошибка: ожидался редирект 302, получен код {connect_resp.status_code}")
            return False, None

        expected_location = f"/private_chat/{new_chat_id}"
        if not connect_resp.headers.get('Location', '').endswith(expected_location):
            print(f"Ошибка: редирект ведёт не на {expected_location}")
            return False, None

        # 6. Проверяем доступ к чату
        chat_resp = session.get(f"{host}/private_chat/{new_chat_id}")
        if chat_resp.status_code != 200:
            print(f"Ошибка доступа к чату (код {chat_resp.status_code})")
            return False, None

        # 7. Отправляем сообщение (флаг или тестовые сообщения)
        sio = socketio.Client()

        cookies = session.cookies.get_dict()
        headers = {
            'Cookie': '; '.join([f"{k}={v}" for k, v in cookies.items()])
        }

        try:
            sio.connect(host, headers=headers, transports=['websocket'])

            sio.emit('join_private_chat', {'chat_id': new_chat_id})

            if flag:
                # Отправляем только флаг
                sio.emit('send_private_message', {
                    'chat_id': new_chat_id,
                    'message': flag
                })
            else:
                # Отправляем 10 тестовых сообщений
                for i in range(1, 11):
                    username = generate_random_username()
                    password = generate_random_password()
                    message_text = f"Логин: {username} / Пароль: {password}"
                    sio.emit('send_private_message', {
                        'chat_id': new_chat_id,
                        'message': message_text
                    })
                
            # Ждем обработки сообщения
            time.sleep(0.2)

        except Exception as e:
            print(f"Ошибка при отправке сообщений через Socket.IO: {str(e)}")
            return False, None
        
        finally:
            if sio.connected:
                sio.disconnect()
                
        elapsed_time = time.time() - start_time
        print(f"Успех! Чат создан, подключение установлено и отправлено сообщение. Время: {elapsed_time:.2f} сек")
        return True, new_chat_id

    except Exception as e:
        print(f"Ошибка при тестировании приватного чата: {str(e)}")
        return False, None

def test_file_operations(session, host, flag=None):
    """Тест работы с файлами, с возможностью записи флага в test_download.txt"""
    print("\n=== Тест работы с файлами ===")

    try:
        start_time = time.time()
        
        # 1. Получаем CSRF токен для страницы файлов
        csrf_token = get_csrf_token(session, f"{host}/my_files")
        if not csrf_token:
            print("Ошибка: не удалось получить CSRF токен для работы с файлами")
            return False, None
        
        # 2. Проверяем наличие файла test_download.txt
        target_file = "test_download.txt"
        test_files = []
        if os.path.exists("test"):
            test_files = [f for f in os.listdir("test") if os.path.isfile(os.path.join("test", f))]
        
        if flag:
            # Создаем временный файл с флагом
            temp_dir = "temp_test_files"
            os.makedirs(temp_dir, exist_ok=True)
            temp_path = os.path.join(temp_dir, target_file)
            with open(temp_path, 'w') as f:
                f.write(flag)
            files = [('files[]', (target_file, open(temp_path, 'rb')))]
        else:
            # Используем существующие файлы из папки "test"
            if not test_files:
                print("Ошибка: в папке 'test' нет файлов для тестирования")
                return False, None
            files = []
            temp_dir = "temp_test_files"
            os.makedirs(temp_dir, exist_ok=True)
            for filename in test_files:
                src_path = os.path.join("test", filename)
                temp_path = os.path.join(temp_dir, filename)
                shutil.copy2(src_path, temp_path)
                files.append(('files[]', (filename, open(temp_path, 'rb'))))
        
        # 3. Загружаем файлы
        upload_data = {
            "csrf_token": csrf_token
        }
        
        upload_resp = session.post(f"{host}/upload_file", 
                                 data=upload_data,
                                 files=files)
        
        # Закрываем файлы после загрузки
        for _, (_, file) in files:
            file.close()
        
        # Удаляем временную папку
        shutil.rmtree(temp_dir)
        
        if upload_resp.status_code != 200:
            print(f"Ошибка загрузки файлов (код {upload_resp.status_code})")
            return False, None
        
        # 4. Проверяем, что файлы появились в списке
        files_resp = session.get(f"{host}/my_files")
        if files_resp.status_code != 200:
            print(f"Ошибка получения списка файлов (код {files_resp.status_code})")
            return False, None
        
        missing_files = []
        if flag:
            if target_file not in files_resp.text:
                print(f"Ошибка: файл {target_file} не найден в списке")
                return False, None
        else:
            for filename in test_files:
                if filename not in files_resp.text:
                    missing_files.append(filename)
            if missing_files:
                print(f"Ошибка: файлы не найдены в списке: {', '.join(missing_files)}")
                return False, None
        
        # 5. Получаем file_id для test_download.txt
        file_id = None
        files_list_resp = session.get(f"{host}/my_files")
        soup = BeautifulSoup(files_list_resp.text, 'html.parser')
        for row in soup.select('table tbody tr'):
            filename_cell = row.select_one('td:first-child')
            if filename_cell and filename_cell.text.strip() == target_file:
                download_link = row.select_one('a[href^="/download/"]')
                if download_link:
                    file_id = download_link['href'].split('/')[-1]
                    break
        
        if not file_id:
            print(f"Ошибка: не удалось найти ID файла {target_file}")
            return False, None
        
        # 6. Скачиваем файл test_download.txt (только для проверки в check)
        if not flag:
            download_resp = session.get(f"{host}/download/{file_id}", stream=True)
            if download_resp.status_code != 200:
                print(f"Ошибка скачивания файла (код {download_resp.status_code})")
                return False, None

            # Создаем папку download, если ее нет
            download_dir = "download"
            os.makedirs(download_dir, exist_ok=True)

            # Определяем имя файла с учетом возможных дубликатов
            base_name, ext = os.path.splitext(target_file)
            file_path = os.path.join(download_dir, target_file)
            counter = 1
            
            while os.path.exists(file_path):
                new_name = f"{base_name}_{counter}{ext}"
                file_path = os.path.join(download_dir, new_name)
                counter += 1

            # Сохраняем файл
            with open(file_path, 'wb') as f:
                for chunk in download_resp.iter_content(chunk_size=8192):
                    f.write(chunk)

            # 7. Удаляем файл test_delete.txt
            target_delete_file = "test_delete.txt"
            if target_delete_file not in test_files:
                print(f"Ошибка: файл {target_delete_file} не найден в тестовых файлах")
                return False, None
            
            files_list_resp = session.get(f"{host}/my_files")
            file_id_delete = None
            soup = BeautifulSoup(files_list_resp.text, 'html.parser')
            for row in soup.select('table tbody tr'):
                filename_cell = row.select_one('td:first-child')
                if filename_cell and filename_cell.text.strip() == target_delete_file:
                    delete_form = row.select_one('form[action^="/delete_file/"]')
                    if delete_form:
                        file_id_delete = delete_form['action'].split('/')[-1]
                        break
            
            if not file_id_delete:
                print(f"Ошибка: не удалось найти ID файла {target_delete_file}")
                return False, None
            
            # Получаем CSRF токен для удаления
            csrf_token = get_csrf_token(session, f"{host}/my_files")
            if not csrf_token:
                print("Ошибка: не удалось получить CSRF токен для удаления файла")
                return False, None
            
            delete_resp = session.post(f"{host}/delete_file/{file_id_delete}", 
                                     data={"csrf_token": csrf_token})
            
            if delete_resp.status_code not in [200, 302]:
                print(f"Ошибка удаления файла (код {delete_resp.status_code})")
                return False, None
            
            # Проверяем, что файл удален
            files_resp = session.get(f"{host}/my_files")
            if target_delete_file in files_resp.text:
                print(f"Ошибка: файл {target_delete_file} не был удален")
                return False, None
        
        elapsed_time = time.time() - start_time
        print(f"Успех! Все операции с файлами выполнены. Время: {elapsed_time:.2f} сек")
        return True, file_id
    
    except Exception as e:
        print(f"Ошибка при тестировании работы с файлами: {str(e)}")
        return False, None

def check(host):
    host = normalize_host(host)
    total_success = True
    
    try:
        # 1. Проверка доступности сервиса
        r = requests.get(f"{host}/")
        if r.status_code != 200:
            print("Ошибка: неверный код ответа от сервиса.")
            return 102
        
        # 2. Проверка регистрации и входа
        session, _, _ = check_registration_login(host)
        if not session:
            print("Ошибка: тест регистрации/входа не пройден")
            return 102
        total_success = total_success and bool(session)
        
        # 3. Проверка публичного чата
        chat_success = test_public_chat(session, host)
        total_success = total_success and chat_success
        
        # 4. Проверка приватного чата
        private_chat_success, _ = test_private_chat(session, host)
        total_success = total_success and private_chat_success
        
        # 5. Проверка работы с файлами
        files_success, _ = test_file_operations(session, host)
        total_success = total_success and files_success
        
        if total_success:
            print("\n=== Все тесты успешно пройдены! ===")
            return 101
        else:
            print("\n=== Некоторые тесты не пройдены ===")
            return 102
        
    except Exception as e:
        print(f"Ошибка соединения: {str(e)}")
        return 102

def put(host, flag_id, flag, vuln):
    host = normalize_host(host)
    try:
        # Регистрация и вход
        session, username, password = check_registration_login(host)
        if not session:
            print("Ошибка: не удалось зарегистрироваться или войти")
            return 102

        if vuln == 1:
            # Сценарий 1: Сохранение флага в приватном чате
            success, new_flag_id = test_private_chat(session, host, flag=flag)
            if not success:
                print("Ошибка: не удалось создать приватный чат или отправить флаг")
                return 102
            # Сохраняем chat_id, username и password как flag_id
            flag_id_data = {
                "chat_id": new_flag_id,
                "username": username,
                "password": password
            }
            print("Флаг успешно установлен в приватном чате.")
            print(json.dumps(flag_id_data), file=sys.stderr)
            return 101

        elif vuln == 2:
            # Сценарий 2: Сохранение флага в файле test_download.txt
            success, new_flag_id = test_file_operations(session, host, flag=flag)
            if not success:
                print("Ошибка: не удалось загрузить файл с флагом")
                return 102
            # Сохраняем file_id, username и password как flag_id
            flag_id_data = {
                "file_id": new_flag_id,
                "username": username,
                "password": password
            }
            print("Флаг успешно установлен в файле.")
            print(json.dumps(flag_id_data), file=sys.stderr)
            return 101

        else:
            print("Ошибка: неизвестный vuln")
            return 102

    except Exception as e:
        print(f"Ошибка запроса в PUT: {str(e)}")
        return 102

def get(host, flag_id, flag, vuln):
    host = normalize_host(host)
    try:
        # Парсим flag_id как JSON
        try:
            flag_id_data = json.loads(flag_id)
            username = flag_id_data.get("username")
            password = flag_id_data.get("password")
            if not username or not password:
                print("Ошибка: в flag_id отсутствуют username или password")
                return 102
        except json.JSONDecodeError:
            print("Ошибка: flag_id должен быть валидным JSON")
            return 102

        # Вход под тем же пользователем
        session = requests.Session()
        csrf_token = get_csrf_token(session, f"{host}/login")
        if not csrf_token:
            print("Ошибка: не удалось получить CSRF токен для входа")
            return 102
        
        login_data = {
            "csrf_token": csrf_token,
            "username": username,
            "password": password,
            "submit": "Войти"
        }
        
        login_resp = session.post(f"{host}/login", 
                                data=login_data,
                                allow_redirects=False)
        
        if login_resp.status_code != 302:
            print(f"Ошибка входа (код {login_resp.status_code})")
            return 102
        
        # Проверяем успешность входа
        account_resp = session.get(f"{host}/account")
        if account_resp.status_code != 200 or username not in account_resp.text:
            print(f"Ошибка: не удалось войти как {username}")
            return 102

        if vuln == 1:
            # Сценарий 1: Получение флага из приватного чата
            chat_id = flag_id_data.get("chat_id")
            if not chat_id:
                print("Ошибка: в flag_id отсутствует chat_id")
                return 102

            chat_resp = session.get(f"{host}/private_chat/{chat_id}")
            if chat_resp.status_code != 200:
                print(f"Ошибка доступа к чату (код {chat_resp.status_code})")
                return 102

            if flag in chat_resp.text:
                print("Флаг успешно получен из приватного чата.")
                return 101
            else:
                print("Флаг не найден в приватном чате.")
                return 102

        elif vuln == 2:
            # Сценарий 2: Получение флага из файла test_download.txt
            file_id = flag_id_data.get("file_id")
            if not file_id:
                print("Ошибка: в flag_id отсутствует file_id")
                return 102

            download_resp = session.get(f"{host}/download/{file_id}", stream=True)
            if download_resp.status_code != 200:
                print(f"Ошибка скачивания файла (код {download_resp.status_code})")
                return 102

            # Сохраняем файл временно для проверки
            temp_dir = "temp_download"
            os.makedirs(temp_dir, exist_ok=True)
            temp_path = os.path.join(temp_dir, "downloaded.txt")
            with open(temp_path, 'wb') as f:
                for chunk in download_resp.iter_content(chunk_size=8192):
                    f.write(chunk)

            # Читаем содержимое файла
            with open(temp_path, 'r') as f:
                content = f.read()

            # Удаляем временный файл
            shutil.rmtree(temp_dir)

            if flag in content:
                print("Флаг успешно получен из файла.")
                return 101
            else:
                print("Флаг не найден в файле.")
                return 102

        else:
            print("Ошибка: неизвестный vuln")
            return 102

    except Exception as e:
        print(f"Ошибка запроса в GET: {str(e)}")
        return 102

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Нужен аргумент: info/check/put/get")
        sys.exit(1)

    action = sys.argv[1]
    host = sys.argv[2] if len(sys.argv) > 2 else DEFAULT_HOST

    if action == "info":
        sys.exit(info())
    elif action == "check":
        sys.exit(check(host))
    elif action == "put":
        if len(sys.argv) < 6:
            print("Недостаточно аргументов для PUT")
            sys.exit(1)
        flag_id, flag, vuln = sys.argv[3], sys.argv[4], int(sys.argv[5])
        sys.exit(put(host, flag_id, flag, vuln))
    elif action == "get":
        if len(sys.argv) < 6:
            print("Недостаточно аргументов для GET")
            sys.exit(1)
        flag_id, flag, vuln = sys.argv[3], sys.argv[4], int(sys.argv[5])
        sys.exit(get(host, flag_id, flag, vuln))
    else:
        print("Неизвестное действие.")
        sys.exit(1)

