ユーザー認証（ID Tokenの検証）・リプレイ攻撃対策
=========

ユーザー認証のためのID Tokenの検証とリプレイ攻撃の対策をしてみましょう。

# 準備

以下のサイトより「Yahoo! ID連携 v2」の「サーバーサイド」のClient IDとClient Secretを発行する。

* https://e.developer.yahoo.co.jp/dashboard/

「コールバックURL」に`http://localhost:8080/callback`を設定する。

# アプリケーション起動

`server.go`のソースコード内の`CLIENT_ID`と`CLIENT_SECRET`に前述で発行したものを指定し、アプリケーションを起動する。

* http://localhost:8080/index

# リプレイ攻撃の解説

OpenID Connectにおけるリプレイ攻撃は、RPのユーザー認証のID Tokenを受け取るエンドポイントに対して、攻撃者があらかじめ通信経路などで傍受したID Tokenを送信することで不正ログインを行う。  
AuthorizationエンドポイントへのリクエストからID Tokenを受信するまでの一連のセッションが同一であることが保証できない場合に生じてしまう可能性がある。  
この攻撃を防ぐためにはOpenID Connectの仕様に定義されている「nonce」を用いることでセッションを担保し、一度使用されたID Tokenの再利用を検知し攻撃を対策することが可能である。  
これはRPのID Tokenによるユーザー認証の一連の処理の中で行う必要がある。

※ サーバーサイドのAuthorization Code Flowの場合、Tokenエンドポイントのリクエスト時にサーバーサイドでID Tokenを受信することになる。  
サーバーサイドでのリプレイ攻撃は、RPのサーバーとAuthorization Serverの間のProxyやDNSサーバーなどを攻撃者が乗っ取ることで行われる可能性がある。  
Authorization Serverの各エンドポイントは大抵TLSで通信先を保証されており、RPのTLSの検証に漏れのある脆弱な実装が存在する、あるいは攻撃者による証明書の改ざんなどの条件も揃う必要があるため、今回は攻撃の体験は省略し対策の実装を行う。

# ユーザー認証とリプレイ攻撃対策の演習

以下の実装を追加し、ユーザー認証とリプレイ攻撃の対策を行う。

## ユーザー認証

* ID Tokenの取得に署名と各Claimを検証しユーザーを認証する。

## リプレイ攻撃対策

* Authorizationエンドポイントのリクエスト時に「nonce」を生成しセッションに紐付ける。
* セッションに紐づけた「nonce」とAuthorization Serverから返却されたID TokenのPayloadにエンコードされている「nonce」の値が一致しているか確認する。

