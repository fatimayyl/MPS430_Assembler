# MSP430 Assembler – Token Ayrıştırmalı

Bu proje, MSP430 mimarisi için geliştirilmiş bir *assembler (derleyici) ve yükleyici (linker/loader)* simülatörüdür. Kullanıcı dostu bir *Tkinter tabanlı GUI (grafik arayüz)* ile assembly kodlarını yazabilir, makine koduna çevirebilir, sembol tablosunu ve sanal bellek durumunu detaylı şekilde inceleyebilirsiniz.

##  Özellikler

- MSP430 komutlarını tanır (MOV, ADD, CALL, JMP vb.)
- .macro, .endm ile makro tanımları
- .text, .data, .bss ve .usect gibi segment destekleri
- Sembol tablosu ve relocation işlemleri
- Token ayrıştırmalı makine kodu görünümü
- Hex formatında *sanal bellek gözlemi*
- Çok sayfalı kod düzenleme desteği
- .objtxt biçiminde nesne dosyası üretimi ve yükleme

##  Kurulum

### Gerekli Modüller
Python 3.7+ yüklü olmalıdır. Ek modül gerekmez çünkü yalnızca tkinter kullanılmıştır (Python ile birlikte gelir).

Aşağıdaki komutla tkinter kurulu değilse yükleyebilirsiniz:

bash
sudo apt-get install python3-tk   # Linux


bash
pip install tk                    # Windows (gerekirse)


##  Kullanım

### 1. Projeyi Çalıştırın

bash
python gui.py


### 2. Arayüzü Tanıyın

- *Kod Alanı*: MSP430 assembly kodlarını yazabileceğiniz bölüm.
- *Çevir (F5)*: Kodu derler, objtxt dosyası üretir ve analizleri başlatır.
- *Belleği Göster*: Sanal bellek dump’ını 16-byte satırlar halinde gösterir.
- *ESTAB*: Control Section tablosu ve sembol adres bilgilerini gösterir.
- *Makro Tanımları*: Yazdığınız .macro blokları otomatik tanımlanır.
- *Makine Kodu Paneli*: Komutların adres, opcode, operand ve binary değerleriyle gösterimi yapılır.

### 3. Kod Örneği
1. Kod örneği:
assembly
.text 0x1100
.global start

start:
    MOV #msg, R4        ; Immediate adres -> relocation
    CALL func           ; External sembol
    JMP end_label       ; Jump relocation

.data 0x0200
msg:   .word var1
var1:  .word 0x1234

func:
end_label:




2. Kod örneği:
assembly
   ;----------------------------
        ; Makro Tanımı
        ;----------------------------
        addfive     .macro   dst
                    ADD.W    #5, dst
                    .endm

        ;----------------------------
        ; Global Semboller
        ;----------------------------
                    .global  var1

        ;----------------------------
        ; Ana Program
        ;----------------------------
                    MOV.W    #0, R11

        ; R11'e 5 kez 5 ekle
                    addfive  R11
                    addfive  R11
                    addfive  R11
                    addfive  R11
                    addfive  R11

        ; R11 içeriğini var1'a yaz
                    MOV.W    R11, &var1




3. Kod Örneği: Otomatik Kütüphane Arama:
Sayfa 1'e ekleyin:
; Sayfa 1 - 5 tane MOV komutu ve ikinci sayfayı çağırma
.text
.org    0x1100

MOV     #0x1234, R4
MOV     #0x5678, R5
MOV     #0x9ABC, R6
MOV     #0xDEF0, R7
MOV     #0x1111, R8

CALL    #SECOND_PAGE 

Sayfa 2'ye ekleyin:
; Sayfa 2 - 50 tane MOV komutu
.text
.org    0x1200
SECOND_PAGE:
MOV     #0x0001, R0
MOV     #0x0002, R1
MOV     #0x0003, R2
MOV     #0x0004, R3
MOV     #0x0005, R4
MOV     #0x0006, R5
MOV     #0x0007, R6
MOV     #0x0008, R7
MOV     #0x0009, R8
MOV     #0x000A, R9
MOV     #0x000B, R10
MOV     #0x000C, R11
MOV     #0x000D, R12
MOV     #0x000E, R13
MOV     #0x000F, R14
MOV     #0x0010, R15
MOV     #0x0011, R0
MOV     #0x0012, R1
MOV     #0x0013, R2
MOV     #0x0014, R3
MOV     #0x0015, R4
MOV     #0x0016, R5
MOV     #0x0017, R6
MOV     #0x0018, R7
MOV     #0x0019, R8
MOV     #0x001A, R9
MOV     #0x001B, R10
MOV     #0x001C, R11
MOV     #0x001D, R12
MOV     #0x001E, R13
MOV     #0x001F, R14
MOV     #0x0020, R15
MOV     #0x0021, R0
MOV     #0x0022, R1
MOV     #0x0023, R2
MOV     #0x0024, R3
MOV     #0x0025, R4
MOV     #0x0026, R5
MOV     #0x0027, R6
MOV     #0x0028, R7
MOV     #0x0029, R8
MOV     #0x002A, R9
MOV     #0x002B, R10
MOV     #0x002C, R11
MOV     #0x002D, R12
MOV     #0x002E, R13
MOV     #0x002F, R14
MOV     #0x0030, R15
MOV     #0x0031, R0
MOV     #0x0032, R1
RET 




##  Proje Yapısı


 MSP430-Assembler
├── assembler.py        # Parser, sembol tablosu, opcode üretimi
├── gui.py              # Tkinter tabanlı kullanıcı arayüzü
├── linking_loader.py   # .objtxt yükleyici, bellek modellemesi
├── output.objtxt       # Üretilen nesne dosyası
└── README.md


##  Geliştirici Bilgisi

Bu sistem, MSP430 işlemcisi mimarisi için eğitim ve analiz amaçlı geliştirilmiştir. Herhangi bir fiziksel donanım gerektirmez ve tüm işlemler yazılım ortamında simüle edilmiştir.

##  Notlar

- .objtxt dosyası her “Çevir” işleminden sonra otomatik üretilir.
- Bellek sadece geçerli segment adresleri (text/data/bss) içinde yazılır.
- Her sembolün adresi symbol_table içinden dinamik olarak elde edilir.

##  İletişim

Bu proje hakkında soru veya katkı için lütfen proje sahibiyle iletişime geçiniz.