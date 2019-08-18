CSRF攻撃体験
=========

CSRF攻撃を体験してみましょう。

# 準備

以下のサイトより「Yahoo! ID連携 v2」の「サーバーサイド」のClient IDとClient Secretを発行する。

* https://e.developer.yahoo.co.jp/dashboard/

「コールバックURL」に`http://localhost:8080/callback`を設定する。

# アプリケーション起動

`server.go`のソースコード内の`CLIENT_ID`と`CLIENT_SECRET`に前述で発行したものを指定し、アプリケーションを起動する。

# 攻撃の体験

攻撃者を想定したユーザーIDでログインし、Authorization Codeを取得する。  
そのAuthorization Codeをredirect_uriへ指定し、被害者を想定してURLへアクセスする。  
被害者が攻撃者のユーザーIDで「乗っ取らせ」ができることを確認する。

# 解説

OpenID ConnectあるいはOAuth 2.0におけるCSRF攻撃は、AuthorizationエンドポイントへのリクエストからAuthorization Codeをサーバーサイドへ送信するまでの一連のセッションが同一であることが保証できない場合に生じてしまう可能性がある。  
攻撃者はAuthorization Codeをサーバーサイドへ送信する処理において、Authorization Codeを置き換え攻撃者のIDで「乗っ取らせ」をし、サービスを利用させることで、被害者の情報を窃取する。  
この攻撃を防ぐためにはOpenID ConnectおよびOAuth 2.0の仕様に定義されている「state」を用いることでセッションを担保し対策することが可能である。

# 対策の演習

以下の実装を追加し、攻撃が対策できていることを確認する。

* Authorizationエンドポイントのリクエスト時に「state」を生成しセッションに紐付ける。
* redirect_uriへリダイレクトし、サーバーサイドでAuthorization Codeを取得する前に発行した「state」とAuthorization Serverから返却された「state」の値が一致しているか確認する。

