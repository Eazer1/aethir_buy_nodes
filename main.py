import json
import time

from web3 import Web3
from eth_account.signers.local import LocalAccount
from eth_account import Account
from loguru import logger

from threading import Thread
from cfg import *

def check_weth_balance(prkey, tier, amount):
    main_acc: LocalAccount = Account.from_key(prkey)
    web3 = Web3(Web3.HTTPProvider(NODE_RPC))

    sale_contract_address = Web3.to_checksum_address(SMART_CONTRACTS[f'tier-{tier}'])
    weth_contract_address = Web3.to_checksum_address(wETH_CONTRACT_ADDRESS)

    weth_contract = web3.eth.contract(weth_contract_address, abi=json.loads(wETH_CONTRACT_ABI))
    sale_contract = web3.eth.contract(sale_contract_address, abi=json.loads(CONTRACT_ABI))

    while True:
        try:
            check_tier_price = sale_contract.functions.salePrice().call()
            wETH_balance_user = weth_contract.functions.balanceOf(main_acc.address).call()

            if wETH_balance_user >= check_tier_price*int(amount):
                return True
            else: return False
        except Exception as e:
            logger.error(f'[{main_acc.address}] {e}')
            time.sleep(5)

def check_approve(prkey, tier, amount):
    main_acc: LocalAccount = Account.from_key(prkey)
    web3 = Web3(Web3.HTTPProvider(NODE_RPC))

    sale_contract_address = Web3.to_checksum_address(SMART_CONTRACTS[f'tier-{tier}'])
    weth_contract_address = Web3.to_checksum_address(wETH_CONTRACT_ADDRESS)

    weth_contract = web3.eth.contract(weth_contract_address, abi=json.loads(wETH_CONTRACT_ABI))
    sale_contract = web3.eth.contract(sale_contract_address, abi=json.loads(CONTRACT_ABI))

    while True:
        try:
            check_tier_price = sale_contract.functions.salePrice().call()
            check_contract_approve = weth_contract.functions.allowance(main_acc.address, sale_contract_address).call()

            if check_contract_approve >= check_tier_price * int(amount):
                return True
            else:
                return False
        except Exception as e:
            logger.error(f'[{main_acc.address}] {e}')
            time.sleep(5)

def approve(prkey, tier, amount):
    main_acc: LocalAccount = Account.from_key(prkey)
    web3 = Web3(Web3.HTTPProvider(NODE_RPC))

    sale_contract_address = Web3.to_checksum_address(SMART_CONTRACTS[f'tier-{tier}'])
    weth_contract_address = Web3.to_checksum_address(wETH_CONTRACT_ADDRESS)

    weth_contract = web3.eth.contract(weth_contract_address, abi=json.loads(wETH_CONTRACT_ABI))
    sale_contract = web3.eth.contract(sale_contract_address, abi=json.loads(CONTRACT_ABI))

    while True:
        try:
            check_tier_price = sale_contract.functions.salePrice().call()

            transaction = weth_contract.functions.approve(sale_contract_address, check_tier_price*int(amount)).build_transaction({
                'from': main_acc.address,
                'value': 0,
                'chainId': web3.eth.chain_id,
                'gasPrice': web3.eth.gas_price,
                'nonce': web3.eth.get_transaction_count(main_acc.address),
            })
            signed_tx = web3.eth.account.sign_transaction(transaction, main_acc._private_key)
            tx_token = web3.eth.send_raw_transaction(signed_tx.rawTransaction)
            tx_token = web3.to_hex(tx_token)
            logger.info(f'[{main_acc.address}][wETH APPROVE FOR SALE CONTRACT] Approve')

            while True:
                try:
                    receipt = web3.eth.wait_for_transaction_receipt(tx_token, timeout = 120)
                    if receipt['status'] == None:
                        logger.info(f'[{main_acc.address}][wETH APPROVE FOR SALE CONTRACT] Wait Status...')
                    elif receipt['status'] == 1:
                        logger.success(f'[{main_acc.address}][wETH APPROVE FOR SALE CONTRACT] Success')
                        return
                    elif receipt['status'] != 1:
                        logger.error(f'[{main_acc.address}][wETH APPROVE FOR SALE CONTRACT] fail. Try again...')
                except: ...
        except Exception as e:
            logger.error(f'[{main_acc.address}] {e}')
            time.sleep(5)

def mint_node(prkey, tier, amount):
    main_acc: LocalAccount = Account.from_key(prkey)
    web3 = Web3(Web3.HTTPProvider(NODE_RPC))

    sale_contract_address = Web3.to_checksum_address(SMART_CONTRACTS[f'tier-{tier}'])
    sale_contract = web3.eth.contract(sale_contract_address, abi=json.loads(CONTRACT_ABI))

    while True:
        try:
            check_tier_price = sale_contract.functions.salePrice().call()
            _allocation = 1000000000000000000*int(amount)

            transaction = sale_contract.functions.whitelistedPurchaseWithCode(check_tier_price*int(amount), [], _allocation, Web3.to_text(hexstr='0x65617a6572')).build_transaction({
                'from': main_acc.address,
                'value': 0,
                'chainId': web3.eth.chain_id,
                'gasPrice': int(web3.eth.gas_price*1.11),
                'nonce': web3.eth.get_transaction_count(main_acc.address),
            })
            signed_tx = web3.eth.account.sign_transaction(transaction, main_acc._private_key)
            tx_token = web3.eth.send_raw_transaction(signed_tx.rawTransaction)
            tx_token = web3.to_hex(tx_token)
            logger.info(f'[{main_acc.address}][mint Node] {tx_token}')

            while True:
                try:
                    receipt = web3.eth.wait_for_transaction_receipt(tx_token, timeout = 120)
                    if receipt['status'] == None:
                        logger.info(f'[{main_acc.address}][mint Node] Wait Status...')
                    elif receipt['status'] == 1:
                        logger.success(f'[{main_acc.address}][mint Node] Success')
                        return
                    elif receipt['status'] != 1:
                        logger.error(f'[{main_acc.address}][mint Node] fail. Try again...')
                except: ...

        except Exception as e:
            logger.error(f'[{main_acc.address}] {e}')

def start(prkey, tier, amount):
    main_acc: LocalAccount = Account.from_key(prkey)
    logger.info(f'[{main_acc.address}] Start')

    check_balance = check_weth_balance(prkey, tier, amount)

    if check_balance == False:
        logger.error(f'[{main_acc.address}] Недоcтаточный баланс wETH')
    else:

        approve_status = check_approve(prkey, tier, amount)
        if approve_status == False:
            approve(prkey, tier, amount)

        logger.info(f'[{main_acc.address}] Ожидаем 5 секунд до старта')
        while True:
            if time.time() > 1710928795:
                break
            else: time.sleep(1)

        mint_node(prkey, tier, amount)

file_name = 'wallets'
accs_list = open(file_name + '.txt', 'r').read().splitlines()

for el in accs_list:
    splited_data = el.split(';')
    prkey = splited_data[0]
    tier = splited_data[1]
    amount = splited_data[2]

    Thread(target=start, args=(prkey, tier, amount)).start()
    time.sleep(0.01)
