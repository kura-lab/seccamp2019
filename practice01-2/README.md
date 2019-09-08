ユーザー識別子による脆弱な認証体験
=========

ユーザー識別子による脆弱な認証を体験してみましょう。

# 準備

以下のサイトより「Yahoo! ID連携 v2」の「クライアントサイド」のClient IDを発行する。

* https://e.developer.yahoo.co.jp/dashboard/

「コールバックURL」に`http://localhost:8080/callback`を設定する。

# アプリケーション起動

`server.go`のソースコード内の`CLIENT_ID`に前述で発行したClient IDを指定し、アプリケーションを起動する。

# 攻撃の体験

準備の手順で別のClient IDを発行し、ID TokenやUserInfoエンドポイントから被害者のユーザー識別子やメールアドレスを取得する。  
クライアントサイドからサーバーサイドへ送信しているユーザー識別子やメールアドレスを置き換えることで他のユーザーでログインできることを確認する。  

# 解説

この実装ではクライアントサイドで取得したユーザー識別子（メールアドレスなどの属性情報）をサーバーサイドへ送信しています。  
他のアプリケーションで発行したユーザー識別子も受け入れてしまい、第三者として不正にログインできてしまう脆弱性につながるため、このような実装はしてはいけません。  
サーバーサイドでAccess Tokenが必要な場合は、OpenID ConnectのAuthorization Code Flowを利用しサーバーサイドでAccess Tokenを取得するようにすべきです。
