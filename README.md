# Aethir Buy Nodes

Aethir Buy Nodes - это автоматизированный инструмент на python, предназначенный для автоматической покупки нод Aethir согласно заданным пользователем характеристикам. Этот инструмент позволяет пользователям указать желаемый тир ноды и количество для покупки, а также автоматически применяет скидку 10%, которую Aethir предоставит через две недели после покупки.

Информация о проекте: https://t.me/Eazercrypto/1079

## Особенности
- Автоматическая покупка нод Aethir согласно заданным характеристикам (тир и количество).
- Применение автоматической скидки 10% на момент покупки с последующим возвратом скидки через две недели.
- Простота настройки и использования.
- Если у вас есть собственная нода Arbitrum, то замените в файле cfg.py значение "NODE_RPC"
- Код можно и даже желательно запустить заранее. Он проверит, хватает ли на ваших кошельках $wETH и сделает апрувы на контракты сейла нод

## Настройка

- Python 3.10

```
git clone https://github.com/Eazer1/aethir_buy_nodes
```
```
cd aethir_buy_nodes
```
```
pip install -r requirements.txt
```

Загрузка в wallets.txt кошельков в формате prkey;tier;amount где:
- prkey - приватный ключ от вашего кошелька
- tier - Тир ноды, который вы планируете купить
- amount -  Количество нод, которое вы планируете купить

Есть возможность построчно загрузить более 1-го кошелька

## Примечание

### Учтите, что:

- tier 1, 2, 3 и 4 ноды может быть только в кол-ве 5, 10, 15, 30 штук соответственно, на всё комьюнити, поэтому эти тиры покупайте не более 1ой штуки на кошелек
- На кошельке нужно иметь токен $wETH, а не $ETH
- Код автоматически делает approve $wETH на адрес покупки нод (не более, чем вы запланировали купить), поэтому не пугайтесь

- Код создан админом канала https://t.me/Eazercrypto
