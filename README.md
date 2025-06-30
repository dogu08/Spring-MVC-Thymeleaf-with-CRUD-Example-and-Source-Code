1. Giriş
1.1 Gerçek Dünya Problemi
Dijitalleşme ile birlikte kitap gibi fiziki materyallerin takibi zorlaşmış, dijital çözümlere ihtiyaç artmıştır. Kütüphaneler, üniversiteler ve bireysel kullanıcılar için kitap yönetimini kolaylaştıran web uygulamaları bu nedenle önem kazanmıştır. Spring Boot gibi modern Java teknolojileri ile bu tür sistemler hızlı ve verimli şekilde geliştirilir bilmektedir.
1.2 Projenin Hedefleri
Bu projenin amacı, Spring Boot MVC yapısını kullanarak kullanıcı giriş sistemi ve kitap yönetimi (CRUD işlemleri) içeren bir web uygulaması geliştirmektir. Ana hedefler şunlardır:
Spring Boot ve Security ile kullanıcı kayıt/giriş sistemi oluşturmak
Admin ve kullanıcı rolleriyle RBAC yapısı kurmak
Thymeleaf ile kullanıcı dostu arayüz tasarımı
JPA ve Hibernate ile veritabanı işlemleri
CSS ile responsive tasarım
Proje, akademik bir başarıdan öte, gerçek dünyada kullanılabilir bir çözüm sunmayı amaçlamaktadır.
1.3 Projenin Amacı
Amaç, Spring Boot teknolojilerini kullanarak uçtan uca bir web uygulaması geliştirme deneyimi kazanmaktır. Bu süreçte öğrenilecek başlıca kavramlar:
Spring Boot mimarisi
MVC tasarım deseni
JPA/Hibernate ile veri yönetimi
Spring Security ile kimlik doğrulama
Thymeleaf ile dinamik sayfalar
Dependency Injection ve IoC kullanımı
Bu proje, teknik bilgi yanında profesyonel yazılım geliştirme becerileri de kazandırmayı hedeflemektedir.
2. Literatür (Benzer Problemlerin Çözümleri)
2.1 Spring Boot Framework
Spring Boot, konfigürasyon yükünü azaltarak hızlı ve üretime hazır Java uygulamaları geliştirmeyi sağlar. Gömülü Tomcat, varsayılan ayarlar ve bağımlılık yönetimi ile geliştiricilere kolaylık sunar.
Projelerde spring-boot-starter-web, thymeleaf, data-jpa gibi bağımlılıklar sayesinde kitap yönetimi gibi sistemler kolayca oluşturulabilir.
GitHub, Java Guides ve Kodgemisi gibi kaynaklarda Spring Boot'un veritabanı bağlantısı, REST API ve kimlik doğrulama gibi birçok örneği bulunmaktadır.
Bu projede de kullanıcı arayüzü Thymeleaf ile, veritabanı işlemleri ise JPA ve Hibernate ile gerçekleştirilmiştir.
2.2 MVC Mimarisi
MVC (Model-View-Controller), uygulamaları üç katmana ayırarak düzenli ve test edilebilir hale getirir.
Spring Boot, bu yapıyı doğal olarak destekler. Örneğin, kitap ekleme işlemi Controller'da karşılanır, Service katmanı aracılığıyla işlenir ve sonuç View katmanında (Thymeleaf) kullanıcıya sunulur.
Baeldung ve JavaGuides gibi kaynaklarda MVC yapısının sürdürülebilirliği artırdığı vurgulanır.
Bu projede de Model (Book, User), View (HTML+CSS+Thymeleaf) ve Controller katmanları açık biçimde ayrılmıştır.
2.3 Dependency Injection (DI)
DI, sınıflar arası bağımlılıkların dışarıdan enjekte edilmesini sağlayarak esneklik ve test kolaylığı sunar.
Spring Boot, @Service, @Repository, @Controller gibi anotasyonlarla bu yapıyı destekler.
Constructor Injection yöntemi sayesinde, örneğin BookController, BookService’i doğrudan kullanmak yerine dışarıdan alır:
@Controller
public class BookController {
    private final BookService bookService;
    public BookController(BookService bookService) {
        this.bookService = bookService;
    }
}

Bu yapı sayesinde test ortamlarında mock sınıflar kolayca entegre edilebilir.
Projede BookService, UserService ve Repository sınıfları DI yöntemiyle kullanılmış, bu da modülerlik ve sürdürülebilirlik sağlamıştır.


3. UML Diyagramı
![umut vpd](https://github.com/user-attachments/assets/9b40fef8-fcd3-4936-bd84-805f8983b74c)

Bu UML sınıf diyagramı, Spring Boot MVC mimarisi kullanılarak geliştirilen bir kitap yönetim sistemi uygulamasının temel bileşenlerini ve bu bileşenler arasındaki ilişkileri göstermektedir. Aynı zamanda kullanıcı kimlik doğrulama, JWT tabanlı güvenlik, ve rol tabanlı erişim kontrolü (RBAC) gibi temel güvenlik özelliklerini de içermektedir.


1.  Varlık (Entity) Sınıfları
  Book
Uygulamanın temel domain nesnesidir.
Kitapların id, title, ve author gibi alanlarını içerir.
Veritabanı tablosunu temsil eder.
Diğer bileşenler (controller, service, repository) bu sınıf üzerinden kitap verisini işler.
  User
Sisteme giriş yapan kullanıcıları temsil eder.
username, password, ve roles gibi alanlara sahiptir.
Kullanıcı-rol ilişkisi çoktan çoğadır (bir kullanıcı birden fazla role sahip olabilir).
 Role
Kullanıcılara atanan sistem yetkilerini temsil eder.
Her rol bir isme (name) sahiptir (örn. ROLE_USER, ROLE_ADMIN).
 Contact
Kullanıcıya ait iletişim bilgilerini barındırır.
Her bir Contact, bir User ile ilişkilidir (bir kullanıcıya birden fazla iletişim bilgisi bağlanabilir).

2.  Katmanlar Arası Bağlantılar
 BookController
HTTP isteklerini karşılar (örn. GET, POST, DELETE).
listBooks(), addBook(Book), deleteBook(id) gibi endpoint’lere sahiptir.
Doğrudan BookService ile iletişime geçer.
Görevi yalnızca yönlendirme ve isteğin dış dünya ile olan etkileşimini yönetmektir (MVC'nin Controller katmanı).
 BookService (Arayüz)
Kitaplarla ilgili iş mantığını tanımlar.
Gerçek uygulama BookServiceImpl sınıfında yapılır.
 BookServiceImpl
BookService arayüzünü uygular.
BookRepository ile çalışarak veritabanına erişir.
Controller’dan gelen istekleri işler ve repository'e yönlendirir.
İş mantığı burada yer alır (örneğin: aynı başlıktaki kitabın eklenmesini engelleme, validasyon vb.).
 BookRepository
JpaRepository'yi genişleterek Spring Data JPA üzerinden CRUD işlemlerini otomatik sağlar.
Veritabanı erişimi bu sınıfta soyutlanmıştır.



3.  Güvenlik Bileşenleri
 JwtTokenProvider
JWT (JSON Web Token) üretiminden ve doğrulamasından sorumludur.
3 temel metodu vardır:
generateToken(User): Giriş yapan kullanıcıya token üretir.
validateToken(token): Token geçerliliğini kontrol eder.
getUsernameFromToken(token): Token içinden kullanıcı adını çeker.
Bu yapı, stateless authentication mekanizmasının temelini oluşturur.
 SecurityConfig
Spring Security yapılandırmasını içerir.
HTTP güvenlik ayarlarını, hangi endpoint’lerin kimlik doğrulama gerektirdiğini, hangi rollerin hangi sayfalara erişebileceğini tanımlar.
Ayrıca passwordEncoder() metodu ile şifreleme mantığını belirler.

4. Kimlik Doğrulama Katmanı
 AuthController
Kullanıcı giriş (login) ve kayıt (register) işlemlerini yönetir.
UserRepository aracılığıyla kullanıcı veritabanına erişir.
Giriş başarılıysa JwtTokenProvider ile JWT üretir ve istemciye döner.
 UserRepository
User nesneleri için veritabanı işlemlerini yönetir.
Genellikle findByUsername(String) gibi özel sorgular içerir.

5. Sınıflar Arası İlişkiler
BookController → BookService: Controller, servis katmanını çağırır.
BookServiceImpl → BookRepository: Servis, veri erişimi için repository’yi kullanır.
User → Role: Çoktan çoğa ilişki (Set<Role>).
User → Contact: Bire çok ilişki (bir kullanıcı birçok iletişim kaydına sahip olabilir).
AuthController → JwtTokenProvider: Token üretimi ve doğrulaması için çağrı yapar.
SecurityConfig → JwtTokenProvider: Güvenlik filtrelerinde token doğrulama için kullanılır.
4. Kullanılan Teknolojiler
Java 17
Spring Boot 3.2.x
Spring Web
Spring Security
Spring Data JPA
Hibernate
Thymeleaf
MySQL
Lombok
HTML, CSS, JavaScript (animasyon)
Postman (test için)

5. Projedeki Uygulamanın Kodlarının Ekran Çıktıları
<img width="1470" alt="1" src="https://github.com/user-attachments/assets/95bf9fee-0a64-4211-895a-d3e6f2ed88d0" />

Bu sayfa, bir kitap uygulamasının ana giriş ekranı olarak tasarlanmış sade ve modern bir arayüzdür. Kullanıcıyı giriş yapmaya veya kayıt olmaya yönlendirir. Ortadaki beyaz kutu içinde hoş geldin mesajı, giriş ve kayıt butonları yer alır. Sayfa, responsive tasarıma, gölgelendirmeye, yumuşak geçişli arka plana ve temiz bir kullanıcı deneyimine sahiptir. Alt kısımda iletişim için bir e-posta adresi yer alır. Genel olarak, kullanıcı dostu ve profesyonel görünümlü bir karşılama sayfasıdır.


<img width="1470" alt="2" src="https://github.com/user-attachments/assets/13d6c35c-5cba-4652-83cd-ee046fd63753" />

Bu ekran görüntüsünde, sol tarafta kitap uygulamasının karşılama sayfası yer almakta; kullanıcıdan giriş yapması veya kayıt olması isteniyor. Sağ tarafta ise, sayfa altındaki e-posta adresine gönderilmek üzere açılmış bir e-posta hazırlama ekranı bulunuyor. E-posta alıcısı olarak abc@abc.com yazılmış. Görsel, kullanıcı arayüzü ile e-posta iletişiminin nasıl entegre çalıştığını göstermektedir.
<img width="1470" alt="3" src="https://github.com/user-attachments/assets/c00b7089-aaa9-4629-b58a-cae352f81859" />

Bu ekran, bir kayıt (register) sayfasını göstermektedir. Kullanıcıdan bir kullanıcı adı (Username) ve şifre (Password)girmesi istenmektedir. Alt kısımda:
Kayıt işlemini tamamlamak için Register butonu,
Ana sayfaya dönmek için Main page bağlantısı,
Zaten hesabı olan kullanıcılar için Login bağlantısı yer almaktadır.
Arayüz sade ve kullanıcı dostudur.
<img width="1470" alt="4" src="https://github.com/user-attachments/assets/5af2b883-0d14-482e-8fe7-e05404d994f6" />

Bu görselde bir giriş (login) ekranı yer almaktadır. Ekran özellikleri:
Başlık: Login
Giriş alanları:
Username (kullanıcı adı): "admin" yazılmış.
Password (şifre): Gizlenmiş olarak yazılmış.
Log in butonu mevcut.
Alt kısımda: ← Back to Main Page (Ana sayfaya dön) bağlantısı var.
Arayüz modern ve sade bir tasarıma sahip; arka plan gradyan renkli.

<img width="1470" alt="5" src="https://github.com/user-attachments/assets/cef666d6-ce4b-4f36-b743-b82424bb7b6a" />

Bu görselde bir kitap takip sistemine ait ana yönetim ekranı yer almakta. Özellikler:
Üst kısımda başlık:
📚 “Kitap Takip Sistemine Hoş Geldiniz – Spring Boot MVC & Thymeleaf Uygulaması”
Giriş yapan kullanıcı: admin
Kitap listesi tablo halinde gösteriliyor:
Sütunlar: Title, Year, Edit, Delete
Örnek kitaplar: The Great Gatsby, 1984, vb.
Her kitap için Edit ve Delete butonları mevcut.
Yeni kitap eklemek için: + Add New Book butonu.
Alt bilgi kısmı: e-posta ve telif hakkı bilgisi içeriyor.
Bu sayfa, bir kitap yönetim panelidir ve CRUD işlemlerini (Create, Read, Update, Delete) destekler.
<img width="1470" alt="6" src="https://github.com/user-attachments/assets/03c1ab09-7fe5-47fa-a227-a052320ddc2f" />

Bu görselde, kitap ekleme (Add New Book) ekranı yer alıyor. Özellikler:
Başlık: Add New Book
Giriş alanları:
Title (Başlık): "Fenerbahçe" yazılmış.
Year (Yıl): "1907" girilmiş.
Altında: Save butonu (veriyi kaydetmek için).
Bu ekran, sistemde yeni bir kitabı veritabanına eklemek için kullanılıyor. Tasarımı sade ve kullanıcı dostu.
<img width="1470" alt="7" src="https://github.com/user-attachments/assets/16b9377e-e0e6-4014-aae1-c25e2fcef006" />

Bu görselde, kitap düzenleme (Edit Book) ekranı gösterilmektedir. Özellikler:
Başlık: Edit Book
Alanlar:
Title: "Fenerbahçe"
Year: "1907"
Altında: Edit Book adlı mavi bir buton yer alıyor.
Bu ekran, mevcut bir kitabın bilgilerini güncellemek için kullanılır. Arayüz sade ve kullanıcı dostudur.
5.1. Projede Gerçekleştirilenler
Bu projede modern bir web uygulamasında bulunması gereken pek çok özellik başarıyla hayata geçirilmiştir. Aşağıda gerçekleştirilen temel yapı ve fonksiyonlar detaylı olarak sıralanmıştır:
 Katmanlı Mimari Kurulumu
Model-View-Controller (MVC) yapısı kullanılarak uygulama katmanlara ayrıldı:
Controller Katmanı: HTTP isteklerini karşılar.
Service Katmanı: İş mantığını yürütür.
Repository Katmanı: Veritabanı işlemlerini gerçekleştirir (JPA üzerinden).
Bu ayrım kodun modüler, bakımı kolay ve test edilebilir olmasını sağladı.
 
Kitap İşlemleri
Book entity’si oluşturuldu ve kitap verileri için temel alanlar tanımlandı.
Kitap ekleme (addBook), silme (deleteBook) ve listeleme (listBooks) işlevleri eklendi.
Tüm işlemler hem arka uçta (backend) hem de uygun HTTP endpoint'ler üzerinden test edildi.
 Kullanıcı Yönetimi ve Kimlik Doğrulama
User ve Role entity’leri oluşturuldu. Roller üzerinden erişim kontrolü sağlandı.
Kullanıcılar için kayıt (register) ve giriş (login) işlemleri geliştirildi.
Spring Security yapılandırmasıyla endpoint güvenliği sağlandı.
 JWT Tabanlı Kimlik Doğrulama
Kullanıcılara giriş yaptıktan sonra JWT token verildi.
Token doğrulama, geçerlilik kontrolü ve kullanıcı adı çıkarma işlemleri JwtTokenProvider aracılığıyla yapıldı.
Token güvenlik filtrelerine entegre edildi.
 Kişi Bilgileri (Contact) Yönetimi
Her kullanıcıya özel kişi bilgileri (Contact) eklendi.
Kullanıcı bazlı sorgular yapılarak yalnızca oturum sahibi kullanıcının kişileri görüntülenebildi.
 Veritabanı Entegrasyonu
Spring Data JPA kullanılarak MySQL/H2 gibi veritabanları ile bağlantı kuruldu.
JpaRepository arayüzü sayesinde CRUD işlemleri kolaylaştırıldı.

5.2. Projede Alınan Hatalar
Projeyi geliştirirken karşılaşılan bazı hatalar ve zorluklar şu şekilde özetlenebilir:
 Dependency (Bağımlılık) Çakışmaları
spring-boot-starter-security, spring-boot-starter-data-jpa ve JWT kütüphaneleri arasında sürüm uyumsuzlukları oldu.
Çözüm: pom.xml dosyasındaki bağımlılıklar düzenlendi ve uygun sürümler belirlendi.

 JWT Token Doğrulama Hataları
İlk denemelerde geçersiz veya süresi dolmuş token’lar düzgün yakalanamadı.
JwtAuthenticationFilter içinde token kontrolü sırasında NullPointerException hatası alındı.
Çözüm: Token null kontrolü ve exception handler mekanizması eklendi.
 CORS Problemleri
Frontend'ten gelen isteklerde CORS hatalarıyla karşılaşıldı.
Çözüm: WebSecurityConfigurerAdapter üzerinden cors() yapılandırması yapıldı.
 Veritabanı Bağlantı Sorunları
Veritabanına bağlanırken yanlış konfigürasyonlardan dolayı Connection Refused hatası alındı.
Çözüm: application.properties veya application.yml dosyaları doğru şekilde güncellendi.
5.3. Projenin Değerlendirilmesi 
 Yapılanlar:
Kitap yönetimi modülü başarıyla geliştirildi.
Kitap ekleme, silme ve listeleme işlemleri sorunsuz çalıştı.
BookController, BookService ve BookRepository katmanları uyumlu şekilde görev yaptı.
JWT tabanlı kullanıcı doğrulama sistemi entegre edildi.
Kullanıcı girişinde token üretimi yapıldı.
Tüm korumalı endpoint’lere erişim sadece geçerli token ile sağlandı.
Rol tabanlı erişim kontrolü kuruldu.
ROLE_USER ve ROLE_ADMIN gibi roller tanımlandı.
Kullanıcının rolüne göre sistemde hangi işlemleri yapabileceği sınırlandı.
Kullanıcı ve iletişim bilgileri ilişkisel olarak yönetildi.
Her kullanıcıya özel Contact verisi eklendi.
Kullanıcıların yalnızca kendi iletişim bilgilerine erişebilmesi sağlandı.
Katmanlı mimariye uygun yapı oluşturuldu.
Controller, Service, Repository ve Entity sınıfları birbirinden ayrıldı.
Kod okunabilirliği ve sürdürülebilirliği artırıldı.

 

Yapılamayanlar:

Frontend (kullanıcı arayüzü) geliştirilemedi.
Proje kapsamında sadece backend kodlarına odaklanıldı.
Gelişmiş arama ve filtreleme özellikleri eklenemedi.
Kitapları yalnızca tüm liste olarak görüntüleme yapılabildi.
Unit test ve entegrasyon testleri yazılamadı.
Testlerin eksikliği, projenin güvenilirliğini sınırlı hale getirdi.
Global hata yönetimi eksik kaldı.
Bazı hatalar sadece konsola yazdırıldı, kullanıcıya anlamlı hata mesajı dönülemedi.
@ControllerAdvice ve @ExceptionHandler gibi yapılar sınırlı düzeyde kullanıldı.
Kullanıcı şifreleri basit şekilde işlendi.
Şifreler BCryptPasswordEncoder ile şifrelenmiş olsa da, kayıt sırasında ek validasyon yapılmadı (örneğin minimum uzunluk, karakter kısıtları).

6. Proje Sonucu
Bu proje sürecinde, Spring Boot tabanlı web uygulaması geliştirme konusunda teorik bilgiler pratik uygulamalarla pekiştirildi. Spring Boot'un resmi dokümantasyonu sayesinde katmanlı mimari, bağımlılık yönetimi ve application.properties dosyası üzerinden yapılandırma işlemleri hakkında derinlemesine bilgi edinildi. Bu bilgiler, projenin yapılandırılmasında doğrudan kullanıldı.
Baeldung kaynakları aracılığıyla, JWT (JSON Web Token) tabanlı kimlik doğrulama sistemlerinin nasıl çalıştığı, güvenliğin Spring Security filtreleri ile nasıl entegre edildiği öğrenildi. Özellikle kullanıcı girişi sonrası token üretimi, her istekle birlikte bu token’ın taşınması ve doğrulama süreçleri detaylı bir şekilde uygulandı. Böylece kullanıcı bazlı güvenli erişim kurgulandı.
YouTube üzerinden izlenen JavaBrains video serileri, konunun görsel ve adım adım anlatımı sayesinde soyut kavramların somut kod örnekleriyle anlaşılmasını sağladı. Videolarda yer alan gerçek zamanlı kodlama örnekleri, projenin geliştirme sürecinde doğrudan referans olarak kullanıldı.
Bu proje sayesinde;
Spring MVC yapısının katmanları (Controller, Service, Repository) arasında nasıl bir görev dağılımı olduğu öğrenildi.
Spring Data JPA kullanılarak veritabanı işlemlerinin ne kadar kolaylaştırılabildiği deneyimlendi.
Kullanıcı ve rollerin yönetimi, güvenlik yapılandırması ve token bazlı oturum kontrolü gibi profesyonel sistemlerin nasıl entegre edileceği uygulamalı olarak öğrenildi.
Ders kapsamında, yazılım mimarisi kuralları, modülerlik, sürdürülebilirlik ve güvenlik gibi yazılım mühendisliğine dair temel kavramların uygulamalı karşılığı görüldü. Bu açıdan proje, teorik bilginin uygulamaya dökülmesini sağlamış; hem teknik hem de metodolojik açıdan önemli bir öğrenme süreci oluşturmuştur.

7. Kaynakça
Spring Boot Documentation – https://docs.spring.io/spring-boot/docs/current/reference/htmlsingle/
Spring Web MVC – https://docs.spring.io/spring-framework/docs/current/reference/html/web.html
Spring Data JPA – https://docs.spring.io/spring-data/jpa/docs/current/reference/html/
Hibernate ORM – https://hibernate.org/orm/documentation/
Thymeleaf – https://www.thymeleaf.org/documentation.html
Lombok – https://projectlombok.org/features/all
Spring Security – https://docs.spring.io/spring-security/reference/index.html
MySQL Docs – https://dev.mysql.com/doc/
Maven Repository – https://mvnrepository.com/
Spring Initializr – https://start.spring.io/
Baeldung Tutorials – https://www.baeldung.com/
Java Guides – https://www.javaguides.net/p/spring-boot-tutorial.html
Callicoder Tutorials – https://www.callicoder.com/spring-boot-thymeleaf-web-app-example/
JetBrains Blog – https://blog.jetbrains.com/idea/tag/spring-boot/
Patika.dev Java Spring Boot Eğitimi – https://www.patika.dev
BTK Akademi Java Spring – https://www.btkakademi.gov.tr/
Medium Makaleleri – https://medium.com/
Mert Mekatronik (YouTube) – https://www.youtube.com/@mertmekatronik
DZone Spring Makaleleri – https://dzone.com/articles/
Dev.to Spring CRUD – https://dev.to/
Kodgemisi - Spring Boot ile Örnek Web Uygulaması – https://medium.com/kodgemisi/spring-boot-ile-%C3%B6rnek-web-uygulamas%C4%B1-914c94c9099f
H2 Database – https://www.h2database.com/html/main.html
Hibernate – https://hibernate.org/
Java Guides Open Source Projects – https://www.javaguides.net/2018/10/free-open-source-projects-using-spring-boot.html
CodeGym Spring Boot Makalesi – https://codegym.cc/tr/groups/posts/tr.311.bolum-8-spring-boot-kullanarak-kucuk-bir-uygulama-
JavaFX Tutorial – https://www.javaguides.net/p/javafx-tutorial.html#google_vignette
Spring Boot GitHub – https://github.com/spring-projects/spring-boot
Spring Boot Framework GitHub – https://github.com/Spring-Boot-Framework
Java Spring Boot GitHub Konuları – https://github.com/topics/java-spring-boot
