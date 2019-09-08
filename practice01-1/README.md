トークン置き換え攻撃体験
=========

トークン置き換え攻撃を体験してみましょう。

# 準備

以下のサイトより「Yahoo! ID連携 v2」の「クライアントサイド」のClient IDを発行する。

* https://e.developer.yahoo.co.jp/dashboard/

「コールバックURL」に`http://localhost:8080/callback`を設定する。

* http://localhost:8080/index

# アプリケーション起動

`server.go`のソースコード内の`CLIENT_ID`に前述で発行したClient IDを指定し、アプリケーションを起動する。

# 攻撃の体験

クライアントサイドからサーバーサイドへ送信しているAccess Tokenを置き換える。  
準備の手順で別のClient IDを発行し、他のユーザーIDでログインしAccess Tokenを取得して置き換える。  
トークンを置き換えることで他のユーザーでログインできることを確認する。

# 解説

この実装ではクライアントサイドで取得したAccess Tokenをサーバーサイドへ送信しています。  
他のアプリケーションで発行したAccess Tokenを受け入れてしまい、第三者として不正にログインできてしまう脆弱性につながるため、このような実装はしてはいけません。  
サーバーサイドでAccess Tokenが必要な場合は、OpenID ConnectのAuthorization Code Flowを利用しサーバーサイドでAccess Tokenを取得するようにすべきです。

