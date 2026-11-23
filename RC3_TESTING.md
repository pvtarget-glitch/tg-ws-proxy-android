# RC3 — сборка и тестирование

## Сборка
1. Откройте Android Build & Release в GitHub Actions, выберите ветку diagnostics/rc3-20261123.
2. Дождитесь jobs rust-test и build; в конце скачайте artifact tg-ws-proxy-android-apks.
3. Для arm64-v8a используйте v8a-minsdk24 или universal APK.
4. Не публикуйте релиз до проверки. Branch push создаёт только artifact; GitHub Release не создаётся автоматически.

Без secrets ANDROID_KEYSTORE_BASE64, ANDROID_KEYSTORE_PASSWORD, ANDROID_KEY_ALIAS и ANDROID_KEY_PASSWORD workflow подпишет APK одноразовым ключом: новую сборку нельзя будет установить поверх APK с иной подписью без удаления старой (сохраните настройки).

## Проверка
1. Запустите через Wi-Fi; проверьте баннер Rust diagnostics build: 1.2.4.1-rc3.
2. Отправьте сообщение, откройте фотографию и видео, запишите время.
3. В разделе «Логи» экспортируйте полный журнал.
4. Повторите с мобильной сетью и сохраните второй журнал.
5. Сопоставьте RC3 NETWORK, RC3 DIAL, RC3 WS, RC3 POOL, RC3 SESSION, RC3 TRANSFER.

first_down_ms=0 означает, что до закрытия сессии не получен первый пакет. avg_down_Bps — средняя скорость по всей длительности сессии, включая паузы.

Не публикуйте личные данные из логов. В RC3 не изменены маршруты и тайм-ауты.
