import base64
import logging, logging.config
import os
from time import sleep
from selenium import webdriver
import warnings
from sqlalchemy import create_engine, Column, Integer, String
from sqlalchemy.orm import declarative_base, sessionmaker, scoped_session
import datetime
from yattag import Doc
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import pandas as pd
import configparser
from cryptography.fernet import Fernet


logging.config.fileConfig("config_dlp.ini")
logger = logging.getLogger('DLP_Log')

list_http = []
list_email = []
list_excel_email = []
report_html = ''

password = ''
cipher = ''

pwd = os.getcwd()
folder_dlp = pwd + '/dlp'
Base = declarative_base()
engine = create_engine('sqlite:///' + pwd + '/DLP_db?check_same_thread=False')  # путь до БД
session_factory = sessionmaker(bind=engine)
session = scoped_session(session_factory)

config = configparser.ConfigParser(interpolation=None)
if not os.path.exists('config_dlp.ini'):
    config["config"] = {
        "address_dlp": "",
        "username": "",
        "list_event": "",
        "path_template": "",
        "host_server": "",
        "email_to": ""
    }
    with open("config_dlp.ini", "w") as file_object:
        config.write(file_object)
    logger.error('Внимание! Нужно заполнить конфигурационный файл!')
config.read("config_dlp.ini", encoding="utf-8")
for value in config['config'].items():
    if value[1] == '':
        logger.error('Параметр '+value[0]+' не задан!')
        input()
        exit()
if not os.path.exists('dlp'):
    os.mkdir('dlp')
if not os.path.exists('report'):
    os.mkdir('report')
warnings.filterwarnings("ignore", category=DeprecationWarning)
profile = webdriver.FirefoxProfile()
profile.set_preference('browser.download.folderList', 2)
profile.set_preference('browser.download.manager.showWhenStarting', False)
profile.set_preference('browser.download.dir', folder_dlp)
profile.set_preference('browser.download.useDownloadDir', True)
profile.set_preference('browser.helperApps.neverAsk.saveToDisk', 'application/octet-stream')
profile.set_preference('general.useragent.override', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/98.0.4758.82 Safari/537.36')
profile.accept_untrusted_certs = True
capabilities = webdriver.DesiredCapabilities().FIREFOX
capabilities['acceptInsecureCerts'] = True
capabilities['marionette'] = True
capabilities['acceptSslCerts'] = True
options = webdriver.FirefoxOptions()
options.headless = True
driver = webdriver.Firefox(firefox_profile=profile, options=options, executable_path='geckodriver.exe')

class Dlp_malware_email(Base):
    __tablename__ = 'malware_email'
    Id = Column(Integer, primary_key=True)
    domain = Column(String, nullable=False)

class Dlp_malware_http(Base):
    __tablename__ = 'malware_http'
    Id = Column(Integer, primary_key=True)
    domain = Column(String, nullable=False)

class Dlp_http(Base):
    __tablename__ = 'http'
    Id = Column(Integer, primary_key=True)
    domain = Column(String, nullable=False)

class Dlp_email(Base):
    __tablename__ = 'mail'
    Id = Column(Integer, primary_key=True)
    domain = Column(String, nullable=False)

def admin_report(report_html):
    try:
        template_html = config['config']['path_template']
        with open(template_html, "rb") as file:
            data = file.read()
        template_html_copy = data.decode()
        doc, tag, text = Doc().tagtext()
        logger.info('Собираю отчет')
        with tag('h1'):
            text('Отчет по обработке событий DLP от: ', str(datetime.datetime.now().strftime("%d.%m.%Y %H:%M")))
        time_html = doc.getvalue()
        if type(report_html) == list:
            doc, tag, text = Doc().tagtext()
            with tag('h2', style='text-align: center; font-size: 1.8em; background-color: #009fff; padding: 10px; border-radius: 10px; color:#ffffff; width: 100%;'):
                text(report_html[0])
            with tag('h3'):
                text(report_html[1])
            report_html = doc.getvalue()
        template_html_copy = template_html_copy.replace("[report_html]", str(report_html))
        template_html_copy = template_html_copy.replace("[time_html]", str(time_html))
        logger.info('Отчет собран')
        f = open('report_dlp.html', 'w', encoding="utf-8")
        f.write(template_html_copy)
        f.close()
    except Exception as e:
        logger.error('Произошла ошибка при сборке отчета ===== ' + str(e))
    try:
        logger.info('Отправляю отчет')
        HOST = config['config']['host_server']
        mail = MIMEMultipart("alternative")
        server = smtplib.SMTP(HOST)
        mail["Subject"] = 'Отчет по обработке событий DLP'
        mail["From"] = 'python_dlp@report.com'
        mail["To"] = config['config']['email_to']
        template = MIMEText(template_html_copy, "html")
        mail.attach(template)
        server.sendmail(mail["From"], mail["To"], mail.as_string())
        server.quit()
        logger.info('Отчет отправлен')
    except Exception as e:
        logger.error('Ошибка при отправке письма отчета ===== ' + str(e))

def create_report_html(report_list_domain, report_list_malware, file):
    try:
        logger.info('Добавляю информацию в отчет из файла '+file+'')
        if not report_list_domain:
            doc, tag, text = Doc().tagtext()
            with tag('h2', style='text-align: center; font-size: 1.8em; background-color: #009fff; padding: 10px; border-radius: 10px; color:#ffffff; width: 100%;'):
                text('Отчет по обработке событий ', file.split('.')[-2])
            with tag('h2', style='text-align: center; width: 100%;'):
                text('Новые домены')
            with tag('h3', style='text-align: center; width: 100%;'):
                text('Новых доменов не обнаружено!')
            doc.stag('br')
            report_domain_html = doc.getvalue()
        else:
            doc, tag, text = Doc().tagtext()
            with tag('h2', style='text-align: center; font-size: 1.8em; background-color: #009fff; padding: 10px; border-radius: 10px; color:#ffffff; width: 100%;'):
                text('Отчет по обработке событий ', file.split('.')[-2])
            with tag('h2', style='text-align: center; width: 100%;'):
                text('Новые домены')
            with tag('table', style='width: 30%; border-right: 3px solid #009fff; border-left: 3px solid #009fff; border-top: 3px solid #009fff; border-collapse: collapse;'):
                with tag('tr', style='background-color: #009fff; text-align: center; font-size: 1.5em;'):
                    with tag('th', style='width: 10px;'):
                        text('№')
                    with tag('th', style='width: 40px;'):
                        text('Домен')
                for i in report_list_domain:
                    with tag('tr', style='text-align: center; font-size: 1.3em; border: 1px solid #009fff;'):
                        style_color = ''
                        style_background = ''
                        if report_list_domain.index(i) % 2 != 0:
                            style_background = 'background-color: #bcbcbc;'
                        if i in report_list_malware:
                            style_color = 'background-color: #ff1616;'
                        with tag('td', style='border-bottom: 3px solid #009fff; '+style_background+' '+style_color+''):
                            text(report_list_domain.index(i) + 1)
                        with tag('td', style='border-bottom: 3px solid #009fff; '+style_background+' '+style_color+''):
                            text(i)
            doc.stag('br')
            report_domain_html = doc.getvalue()
        if not report_list_malware:
            doc, tag, text = Doc().tagtext()
            with tag('h2', style='text-align: center; width: 100%;'):
                text('Вредоносные домены')
            with tag('h3', style='text-align: center; width: 100%;'):
                text('Вредоносных доменов не обнаружено!')
            doc.stag('br')
            report_malware_html = doc.getvalue()
        else:
            doc, tag, text = Doc().tagtext()
            with tag('h2', style='text-align: center; width: 100%;'):
                text('Вредоносные домены')
            with tag('table', style='width: 30%; border-right: 3px solid #009fff; border-left: 3px solid #009fff; border-top: 3px solid #009fff; border-collapse: collapse;'):
                with tag('tr', style='background-color: #009fff; text-align: center; font-size: 1.5em;'):
                    with tag('th', style='width: 10px;'):
                        text('№')
                    with tag('th', style='width: 40px;'):
                        text('Домен')
                for i in report_list_malware:
                    style_background = ''
                    if report_list_malware.index(i) % 2 != 0:
                        style_background = 'background-color: #bcbcbc;'
                    with tag('tr', style='text-align: center; font-size: 1.3em; border: 1px solid #009fff; '):
                        with tag('td', style='border-bottom: 3px solid #009fff; '+style_background+''):
                            text(report_list_malware.index(i) + 1)
                        with tag('td', style='border-bottom: 3px solid #009fff; '+style_background+''):
                            text(i)
            doc.stag('br')
        report_malware_html = doc.getvalue()
        global report_html
        report_html = report_html + report_domain_html + report_malware_html
        logger.info('Информация добавлена в отчет')
    except Exception as e:
        logger.error('Произошла ошибка при составлении отчета ===== ' + str(e))

def add_domain_email(list_excel_email, file):
    logger.info('Добавляю домены события '+file+' в БД')
    try:
        report_list_malware_email = []
        report_list_email = []
        list_email_db = [x.domain for x in session.query(Dlp_email.domain)]
        list_malware_db = [x.domain for x in session.query(Dlp_malware_email)]
        for x in list_excel_email:
            if x in list_malware_db:
                report_list_malware_email.append(x)
        if list_email_db:
            report_list_email = list(set(list_excel_email) - set(list_email_db))
        else:
            report_list_email = list_excel_email
        for item in report_list_email:
            new_domain_email = Dlp_email()
            new_domain_email.domain = item
            session.add(new_domain_email)
            session.commit()
        logger.info('Домены добавлены')
        create_report_html(report_list_email, report_list_malware_email, file)
    except Exception as e:
        logger.error('Ошибка при добавлении Email доменов ===== ' + str(e))

def add_domain_http(list_excel_http, file):
    try:
        logger.info('Добавляю домены события ' +file+' в БД')
        report_list_malware_http = []
        report_list_http = []
        list_http_db = [x.domain for x in session.query(Dlp_http.domain)]
        list_malware_db = [x.domain for x in session.query(Dlp_malware_http)]
        for x in list_excel_http:
            if x in list_malware_db:
                report_list_malware_http.append(x)
        if list_http_db:
            report_list_http = list(set(list_excel_http) - set(list_http_db))
        else:
            report_list_http = list_excel_http
        for item in report_list_http:
            new_domain_http = Dlp_http()
            new_domain_http.domain = item
            session.add(new_domain_http)
            session.commit()
        logger.info('Домены добавлены')
        create_report_html(report_list_http, report_list_malware_http, file)
    except Exception as e:
        logger.error('Ошибка при добавлении HTTP доменов ===== ' + str(e))

def check_str_email(line):
    try:
        global list_excel_email
        line = str(line.strip())
        if '=' in line:
            return
        if '@' in line:
            line = line.split('@')
            domain = line[1]
            if not domain in list_excel_email:
                list_excel_email.append(domain)
    except Exception as e:
        logger.error('Ошибка при обработке email доменов ===== ' + str(e))

def data_processing_email(file):
    try:
        logger.info('Получаю домены из файла '+file+'')
        global list_excel_email
        files = os.listdir('./dlp')
        read_file = pd.read_excel('./dlp/'+file, sheet_name = 1, header = 0, index_col = None)['Получатели'].tolist()
        for i in read_file:
            if ',' in i:
                i = i.split(',')
                for ii in i:
                    check_str_email(ii)
            else:
                check_str_email(i)
        list_excel_email.sort()
        logger.info('Домены из файла '+file+' получены')
        add_domain_email(list_excel_email, file)
    except Exception as e:
        logger.error('Ошибка при обработке файла '+file+' ===== ' + str(e))

def data_processing_http(file):
    try:
        logger.info('Получаю домены из файла '+file+'')
        files = os.listdir('./dlp')
        list_excel_http = []
        read_file = pd.read_excel('./dlp/'+file, sheet_name = 1, header = 0, index_col = None)['Получатели'].tolist()
        for i in read_file:
            i = i.split('.')
            if all(x.isdigit() for x in i):
                continue
            domain = i[-2]+'.'+i[-1]
            if not domain in list_excel_http:
                list_excel_http.append(domain)
        list_excel_http.sort()
        logger.info('Домены из файла '+file+' получены')
        add_domain_http(list_excel_http, file)
    except Exception as e:
        logger.error('Ошибка при обработке файла '+file+' ===== ' + str(e))

def events_processing():
    files = os.listdir('./dlp')
    for file in files:
        if 'email' in file:
            data_processing_email(file)
        if 'http' in file:
            data_processing_http(file)
    admin_report(report_html)

def check_password():
    global password
    global cipher
    if password == '':
        logger.info('Запрашиваю пароль')
        text = input('Введите пароль\n').encode()
        key = base64.b64encode(bytes(Fernet.generate_key().decode(), 'utf-8'))
        cipher = Fernet(base64.b64decode(key))
        password = cipher.encrypt(text)

def start():
    try:
        logger.info('Старт работы')
        global password
        global cipher
        check_password()
        list_event = (config['config']["list_event"]).split(',')
        driver.implicitly_wait(10)
        for f in os.listdir(folder_dlp):
                os.remove(os.path.join(folder_dlp,f))
        sleep(2)
        logger.info('Подключаюсь к DLP')
        driver.get(config['config']['address_dlp'])
        sleep(2)
        driver.find_element_by_name('username').send_keys(config['config']['username'])
        sleep(2)
        elem = driver.find_element_by_name('password')
        elem.send_keys(cipher.decrypt(password).decode())
        sleep(1)
        driver.find_element_by_xpath("//button[contains(text(), 'Войти')]").click()
        sleep(5)
        logger.info('Авторизовался')
        driver.refresh()
        sleep(5)
        driver.find_element_by_xpath("//a[contains(text(), 'События')]").click()
        for event in list_event:
            logger.info('Собираю события '+event+'')
            driver.find_element_by_xpath("//span[contains(@class, 'fancytree-title') and contains(text(), '"+str(event)+"')]").click()
            sleep(2)
            driver.find_element_by_xpath("//button[@class = '[ b-button _icon ] [ icon _play ]']").click()
            time_await = 0
            while 1:
                if driver.find_elements_by_xpath("//section[@class = '[ content__indent _scrollable ] event__content _spinner']"):
                    sleep(10)
                    time_await = time_await + 1
                else:
                    break
                if time_await > 6:
                    print('Error')
                    input()
            driver.find_element_by_id('toolbarDropdownButton').click()
            logger.info('События собраны, начинаю скачивание')
            sleep(2)
            driver.find_element_by_xpath("//button[contains(text(), 'Выгрузить все события')]").click()
            elem = driver.find_element_by_name('DISPLAY_NAME')
            elem.clear()
            elem.send_keys(event)
            if driver.find_element_by_xpath("//label[contains(text(), 'Что выгрузить')]").is_displayed():
                check = driver.find_element_by_xpath("//input[@name='IS_SEVERAL_REPORT' and @type='checkbox']")
                driver.execute_script("arguments[0].style.display = 'block';", check)
                check.click()
            driver.find_element_by_xpath("//button[@name='misc' and @class='[ b-button _success ]']").click()
            time_await = 0
            while 1:
                if driver.find_elements_by_xpath("//i[@class = '[ icon _spinner ]']"):
                    sleep(10)
                    time_await = time_await + 1
                else:
                    break
            sleep(5)
            logger.info('Скачиваю файл '+event+'')
            driver.find_element_by_xpath("/html/body/div[1]/div/header/nav/div[3]/div/section/div/div/div/div/div[2]/div[2]/div/div[1]/div/div[4]/div[3]/div/div/div[1]/div[2]/span/span[2]/a").click()
            sleep(5)
            if driver.find_elements_by_xpath("//button[contains(text(), 'Advanced…')]"):
                driver.find_element_by_xpath("//button[contains(text(), 'Advanced…')]").click()
                driver.find_element_by_xpath("//button[contains(text(), 'Accept the Risk and Continue')]").click()
        logger.info('Начинаю обработку событий')
        events_processing()
        logger.info('Завершение работы')
        driver.__exit__()
    except Exception as e:
        logger.error('Произошла ошибка! ===== ' + str(e))
        driver.__exit__()
        exit()
start()
