# Encrypted Security Code Manager - iOS

## Intro
Esta librería provee métodos para el guardado del CVV encriptado en el dispositivo del usuario. Además se tiene un método para obtener el ESC guardado y para borrar uno en particular o borrar todos.

En iOS se guardan los datos en el keychain bajo el nombre de la aplicación.

Los métodos para guardar y obtener el ESC hacen una verificación en el dispositivo antes de ejecutar su tarea. Esta verificación consiste en validar que el dispositivo tenga alguna forma de protección configurada. En iOS éstas son: PIN, touchID o contraseña. Si el dispositivo no tiene protección se borran del mismo todos los ESC anteriormente guardados.
## Instalación

```ruby
 pod 'ESCManager', '~> 1.0.0'
```

## Uso

### Swift
+ Para obtener el CVV encriptado de un card ID. Si no se encuentra nada devuelve un string vacio.
```swift
ESCManager.getESC(cardId: String) -> String
```
+ Para guardar un CVV encriptado. Si ya habia un ESC guardado para ese Card ID, este se actualiza o se borra dependiendo si el ESC nuevo esta vacio. Si se puede guardar el CVV encriptado, este método devuelve true.
```swift
ESCManager.saveESC(cardId: String, esc: String) -> Bool
```
+ Para borrar un CVV encriptado.
```swift
ESCManager.deleteESC(cardId: String)
```
+ Para borrar todos los CVV encriptados guardados.
```swift
ESCManager.deleteAllESC()
```
+ Para obtener todos los cards Ids que tienen un ESC asociado guardado.
```swift
ESCManager.getSavedCardIds() -> [String]
```

### Objective-C
+ Para obtener el CVV encriptado de un card ID. Si no se encuentra nada devuelve un string vacio.
```objective-c
[ESCManager getESCWithCardId:@"Card-ID"];
```
+ Para guardar un CVV encriptado. Si ya habia un ESC guardado para ese Card ID, este se actualiza o se borra dependiendo si el ESC nuevo esta vacio. Si se puede guardar un dato, este método devuelve true.
```objective-c
[ESCManager saveESCWithCardId:@"Card-ID" esc:@"ESC"];
```
+ Para borrar un CVV encriptado.
```objective-c
[ESCManager deleteESCWithCardId:@"Card-ID"];
```
+ Para borrar todos los CVV encriptados guardados.
```objective-c
[ESCManager deleteAllESC];
```
+ Para obtener todos los cards Ids que tienen un ESC asociado guardado.
```swift
[ESCManager getSavedCardIds];
```

