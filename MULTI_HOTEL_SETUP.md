# Çok Otelli Sistem Kurulumu

Bu sistem, tek bir kod tabanı ile birden fazla oteli yönetmenize olanak tanır. Her otel kendi veritabanına ve kendi e-posta bildirim adresine sahip olabilir.

## Nasıl Çalışır?

1. Her otel için ayrı bir Cloud Run servisi oluşturulur (örn. `hotel1-backend`, `hotel2-backend`)
2. Her servis kendi çevresel değişkenlerine sahiptir:
   - `HOTEL_NAME`: Otel adı
   - `DB_NAME`: MongoDB veritabanı adı
   - `ADMIN_EMAIL`: Bildirimlerin gönderileceği e-posta adresi

## Yeni Otel Ekleme

Yeni bir otel eklemek için GitHub workflow dosyasını (`.github/workflows/deploy.yml`) düzenleyin:

```yaml
strategy:
  matrix:
    hotel:
      - { name: "Hotel One", db_name: "GreenP", admin_email: "nihat.saydam@icloud.com", service_prefix: "hotel1" }
      - { name: "Hotel Two", db_name: "HotelTwo", admin_email: "nihat.saydam@icloud.com", service_prefix: "hotel2" }
      # Yeni bir otel ekleyin:
      - { name: "Yeni Otel", db_name: "YeniOtelDb", admin_email: "yeni@email.com", service_prefix: "yeniotel" }
```

Her otel için aşağıdaki bilgileri belirtmeniz gerekir:
- `name`: Otel adı (e-postalarda görünür)
- `db_name`: MongoDB veritabanı adı
- `admin_email`: Bildirimlerin gönderileceği e-posta adresi
- `service_prefix`: Cloud Run servis adı için önek (yalnızca alfanümerik ve tire karakterleri içerebilir)

## Yeni Veritabanları

Her otelin veritabanı, ilk kayıt oluşturulduğunda MongoDB Atlas'ta otomatik olarak oluşturulacaktır. Ancak, gerekirse MongoDB Atlas kontrol panelinden manuel olarak da oluşturabilirsiniz.

## Frontend Yapılandırması

Frontend kodunuzu her otelin kendi backend URL'sini kullanacak şekilde yapılandırmanız gerekecektir. Örneğin:

```javascript
// Hotel One için
const API_URL = "https://hotel1-backend-xxxx.a.run.app";

// Hotel Two için
const API_URL = "https://hotel2-backend-xxxx.a.run.app";
```

## Nasıl Test Edilir?

Her servisin düzgün çalıştığını test etmek için, Cloud Run konsolundan her otelin URL'sine giderek kontrol edebilirsiniz. Ayrıca, her otelin API endpoint'lerini test etmek için Postman veya benzer bir araç kullanabilirsiniz. 