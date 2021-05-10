from multiprocessing.pool import ThreadPool as Pool
from genAccounts import generate_accounts
from time import gmtime, strftime
from rlp.sedes import binary, big_endian_int
from eth_typing import HexStr
from eth_utils import to_bytes
from var import *
from keys import *
import sys
import json
import os
import time
import rlp



# uniswapTokenSwap_router contract 
uniswapTokenSwap_contract_abi = json.loads(contracts["uniswapTokenSwap_abi"])
uniswapTokenSwap_contract_address = Web3.toChecksumAddress(contracts["uniswapTokenSwap"])
uniswapTokenSwap_router_contract = web3.eth.contract(address=uniswapTokenSwap_contract_address, abi=uniswapTokenSwap_contract_abi)

# uniswaprouter contract 
uniswapRouter_contract_abi = json.loads(contracts["uniswapv2_abi"])
uniswapRouter_contract_address = Web3.toChecksumAddress(contracts["uniswapv2_router"])
uniswapRouter_router_contract = web3.eth.contract(address=uniswapRouter_contract_address, abi=uniswapRouter_contract_abi)

bait_contract_abi = json.loads(contracts["uniswapv2_abi"])
bait_contract_address = Web3.toChecksumAddress(contracts["uniswapv2_router"])
bait_router_contract = web3.eth.contract(address=bait_contract_address, abi=bait_contract_abi)

if(len(sys.argv) > 2 and str(sys.argv[1]) == "strategy_bscstarter_liquidity" and len(sys.argv) > 3):
    bscstarter = json.loads(contracts["bscstarter_abi"])
    bscstarter_contract_address = str(Web3.toChecksumAddress(sys.argv[3]))
    bscstarter_contract = web3.eth.contract(address=bscstarter_contract_address, abi=bscstarter)

token_arguments = ["buy", "getestimate", "withdraw_toaddress", "buy_strategy", "buy_bscstarter", "claim_bscstarter", "bscstarter_send_to_cocontract", "sell", "sell_strategy", "getprice", "withdraw", "remove", "bought", "strategy", "strategy_bscstarter_liquidity", "strategy_bscstarter", "strategy_ww", "mempool"]
arguments = ["help", "createaccounts", "getprice", "fund_accounts", "getestimate", "withdraw_toadmin", "withdraw_toadmin_bscstarter", "gettx", "gettxreceipt", "iscaller", "addcallers" ,"buy", "buy_strategy", "buy_bscstarter", "claim_bscstarter", "bscstarter_send_to_cocontract", "sell", "sell_strategy", "withdraw", "remove", "bought", "strategy", "strategy_bscstarter_liquidity", "strategy_bscstarter", "strategy_ww", "mempool"]
help =  """  

            \33[32mhelp:\x1b[0m prints this menu
            \33[32mcreateaccounts:\x1b[0m create new keypairs and save them to disk usage: python3 main.py createaccounts number_of_accounts
            \33[32mfund_accounts:\x1b[0m pfunds the accounts in the cakeswap array usage: python3 main.py fund_accounts amount
            \33[32mgettx:\x1b[0m prints txinfo usage: python3 main.py gettx txhash
            \33[32mmempool:\x1b[0m detects addliquidity transactions in mempool for a certain token usage: python3 main.py mempool token
            \33[32mgettxreceipt:\x1b[0m prints tx receipt of a given txhash usage: python3 main.py gettxreceipt txhash
            \33[32mgetestimate:\x1b[0m gets the estimated value of a token amount in bnb usage: python3 main.py getestimate token amount
            \33[32mwithdraw_toadmin:\x1b[0m withdraw from the cakeswap addresses to the admin address usage: python3 main.py withdraw_toadmin
            \33[32mwithdraw_toadmin_bscstarter:\x1b[0m withdraw from the bscstarter addresses to the admin address usage: python3 main.py withdraw_toadmin_bscstarter
            \33[32miscaller:\x1b[0m return if the address in question is an approved caller of the contract usage: python3 main.py iscaller adress
            \33[32maddcallers:\x1b[0m add the addresses in cackeswap array in keys.py into the approved callers usage: python3 main.py addcallers
            \33[32mbuy:\x1b[0m buys a token with BNB amount to spend at max price usage: python3 main.py buy Token_contrat amount_to_spend maximum_price
            \33[32mbuy_strategy:\x1b[0m like buy but starts spamming tx buys before liquidity is added to the pool usage: python3 main.py buy_strategy Token_contrat amount_to_spend maximum_price
            \33[32mbuy_bscstarter:\x1b[0m buys a token with BNB amount with the bscstarter addresses usage: python3 main.py buy_bscstarter bscstarter_contract amount_to_spend headstart_in_minutes
            \33[32mclaim_bscstarter:\x1b[0m claims the tokens already bought from the bscstarter addresses usage: python3 main.py claim_bscstarter bscstarter_contract
            \33[32mbscstarter_send_to_cocontract:\x1b[0m sends the tokens already claimed from the bscstarter addresses to the contract usage: python3 main.py bscstarter_send_to_cocontract token
            \33[32msell:\x1b[0m sells a percentage of token holding at min price usage: python3 main.py sell Token_contrat pecentage_amount_to_sell minimum_price
            \33[32msell_strategy:\x1b[0m same as sell but sells a predefine amount instead of percentage usage: python3 main.py sell_strategy Token_contrat amount_to_sell minimum_price
            \33[32mbought:\x1b[0m shows the amount paid for a token in BUSD usage: python3 main.py bought Token_contrat
            \33[32mgetprice:\x1b[0m gets the token price is BUSD usage: python3 main.py getprice Token_contrat
            \33[32mremove:\x1b[0m removes bought token from contract storage (to be able to buy again) usage: python3 main.py remove Token_contrat
            \33[32mwithdraw:\x1b[0m withdraw token and ETH balances from the contract usage: python3 main.py withdraw Token_contrat
            \33[32mstrategy:\x1b[0m a strategy to spam buys/sells for a token at certain prices usage: python3 main.py strategy Token_contrat amount_to_spend maximum_buy_price minimum_sell_price sell_pecentage
            \33[32mstrategy_bscstarter_liquidity:\x1b[0m a strategy to spam buys/sells for a token listed at bscstarter usage: python3 main.py strategy_bscstarter_liquidity Token_contrat bscstarter_contract amount_to_spend maximum_buy_price minimum_sell_price sell_pecentage
            \33[32mstrategy_bscstarter:\x1b[0m a strategy to buys/sells bscstarter projects using the bscstarter addresses usage: python3 main.py strategy_bscstarter Token_contrat bscstarter_contract amount_to_spend minimum_sell_price sell_pecentage
            \33[32mstrategy_ww:\x1b[0m same as strategy but for whitelisted tokens usage: python3 main.py strategy_ww Token_contrat amount_to_spend maximum_buy_price minimum_sell_price sell_pecentage
        """

failCodes = [
            "0x08c379a000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000011507269636520697320746f6f2068696768000000000000000000000000000000", # Price is too high
            "0x08c379a000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000014746f6b656e20616c726561647920626f75676874000000000000000000000000", # token already bought
            "0x08c379a00000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000f4e6f7420616e20696e766573746f720000000000000000000000000000000000", # Not an investor
            "0x08c379a00000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000001741646472657373206e6f742077686974656c6973746564000000000000000000", # Address not whitelisted
            ]

pool, liquidity, raw_transactions, transaction_params, bscstarter_transactions, bscstarter_mission, claimed = [], [], {}, {}, {}, {}, 0


class Transaction(rlp.Serializable):
    fields = [
        ("nonce", big_endian_int),
        ("gas_price", big_endian_int),
        ("gas", big_endian_int),
        ("to", binary),
        ("value", big_endian_int),
        ("data", binary),
        ("v", big_endian_int),
        ("r", big_endian_int),
        ("s", big_endian_int),
    ]

def hex_to_bytes(data: str) -> bytes:
    return to_bytes(hexstr=HexStr(data))

def liquidity_ping(node):
    try:
        remote_node = Web3(Web3.HTTPProvider(node))
        remote_node.middleware_onion.inject(geth_poa_middleware, layer=0)
        tx = liquidity[0][3]
        rawtx = Web3.toHex(rlp.encode(Transaction(nonce=tx.nonce, gas_price=tx.gasPrice, gas=tx.gas, to=hex_to_bytes(tx.to), value=tx.value, data=hex_to_bytes(tx.input), v=tx.v, r=Web3.toInt(tx.r), s=Web3.toInt(tx.s))))
        tx_hash = web3.eth.sendRawTransaction(rawtx)
        print(f'{strftime("%d/%m/%Y %H:%M:%S", gmtime())}: pinged other nodes with tx: {str(tx_hash)}')
    except Exception as e:
        print(f'{strftime("%d/%m/%Y %H:%M:%S", gmtime())}: {str(e)}')

def mempool_check(event):
    try:
        tx = web3.eth.get_transaction(event)
        if(str(tx.to) == str(uniswapRouter_contract_address)):
            try:
                input = uniswapRouter_router_contract.decode_function_input(tx.input)
                if("addLiquidityETH" in str(input) and str(input[1]["token"]) == str(tokenB)):
                    txn = uniswapRouter_router_contract.functions.addLiquidityETH(input[1]["token"], input[1]["amountTokenDesired"], input[1]["amountTokenMin"], input[1]["amountETHMin"], input[1]["to"], input[1]["deadline"]).buildTransaction({
                        'chainId': nodes["chainId"],
                        'from': tx['from'],
                        'nonce': tx['nonce'],
                        'gasPrice': tx['gasPrice'],
                        'gas': tx['gas'],
                        'value': tx['value']})
                    simulate_tx = web3.eth.call(txn)
                    if(Web3.toHex(tx['value'])[2:] in Web3.toHex(simulate_tx)):
                        liquidity.append([True, tx.gasPrice, Web3.toHex(event), tx])
            except:
                pass
        # if(str(sys.argv[1]) == "strategy_bscstarter_liquidity" and str(tx.to) == str(sys.argv[3])):
        #     try:
        #         input = bscstarter_contract.decode_function_input(tx.input)
        #         if("addLiquidityAndLockLPTokens" in str(input)):
        #             txn = bscstarter_contract.functions.addLiquidityAndLockLPTokens().buildTransaction({
        #                 'chainId': nodes["chainId"],
        #                 'from': tx['from'],
        #                 'nonce': tx['nonce'],
        #                 'gasPrice': tx['gasPrice'],
        #                 'gas': tx['gas'],
        #                 'value': tx['value']})
        #             simulate_tx = web3.eth.call(txn)
        #             if(Web3.toHex(simulate_tx) == "0x"):
        #                 liquidity.append([True, tx.gasPrice, Web3.toHex(event), tx])
        #     except:
        #         pass
    except:
        pass

def mempool(token):
    try:
        pool = Pool(processes=nodes["pool_size"])
        filter = web3.eth.filter('pending')
    except:
        print(f'{strftime("%d/%m/%Y %H:%M:%S", gmtime())}: couldn\'t subscribe to pending transactions filter')
    else:
        counter = 0
        while True:
            events = filter.get_new_entries()
            pool.map_async(mempool_check, events, callback=None, error_callback=None)
            counter += len(events) 
            if(len(liquidity) > 0):
                return liquidity
            print(f'{strftime("%d/%m/%Y %H:%M:%S", gmtime())}: ended the mempool scan, new scanned: {str(len(events))} TXs, total scanned: {str(counter)}')
            time.sleep(0.1)

def SwapETHtoTokenB(token: str,  maxTokenPrice: int, amountBNBToSpend: int):
    txn = uniswapTokenSwap_router_contract.functions.SwapETHtoToken(Web3.toChecksumAddress(token), amountBNBToSpend, maxTokenPrice).buildTransaction({
        'chainId': nodes["chainId"],
        'from': Web3.toChecksumAddress(keys["my_account"]),
        'nonce': web3.eth.getTransactionCount(Web3.toChecksumAddress(keys["my_account"])),
        'value': 0,
        'gas': nodes["gas_limit"],
        'gasPrice': web3.toWei(nodes["gas_price"], 'gwei')})
    try:
        simulate_tx = web3.eth.call(txn)
    except Exception as e:
        if("Price is too high" in str(e)):
            print(strftime("%d/%m/%Y %H:%M:%S", gmtime()) + ": Mission failed, the price is already too high!")
            pool.close()
            pool.join()
            return False
        if("token already bought" in str(e)):
            print(strftime("%d/%m/%Y %H:%M:%S", gmtime()) + ": Succusfully Bought!")
            pool.close()
            pool.join()
            return True
        else:
            print(strftime("%d/%m/%Y %H:%M:%S", gmtime()) + ": can't simulate tx " + str(e))
            return False
    else:
        try:
            signed_tx = web3.eth.account.signTransaction(txn, keys["private_key"])
            tx_hash = web3.eth.sendRawTransaction(signed_tx.rawTransaction)
            print(strftime("%d/%m/%Y %H:%M:%S", gmtime()) + ": " + web3.toHex(tx_hash))
            tx_receipt = web3.eth.waitForTransactionReceipt(tx_hash)
            if(tx_receipt["status"]):
                print(strftime("%d/%m/%Y %H:%M:%S", gmtime()) + ": tx was executed successfully")
                return True
        except Exception as e:
            print(strftime("%d/%m/%Y %H:%M:%S", gmtime()) + ": tx failed " + str(e))
            return False

def swapERC20toETH(token: str, tokenAmount: int):
    txn = uniswapTokenSwap_router_contract.functions.swapExactERC20toETH(Web3.toChecksumAddress(token), tokenAmount).buildTransaction({
        'chainId': nodes["chainId"],
        'from': Web3.toChecksumAddress(keys["my_account"]),
        'nonce': web3.eth.getTransactionCount(Web3.toChecksumAddress(keys["my_account"])),
        'value': 0,
        'gas': nodes["gas_limit"],
        'gasPrice': web3.toWei(nodes["sell_gas_price"], 'gwei')})
    #print(str(web3.eth.call(txn)))
    signed_tx = web3.eth.account.signTransaction(txn, keys["private_key"])
    tx_hash = web3.eth.sendRawTransaction(signed_tx.rawTransaction)
    print(strftime("%d/%m/%Y %H:%M:%S", gmtime()) + ": " + web3.toHex(tx_hash))
    tx_receipt = web3.eth.waitForTransactionReceipt(tx_hash)
    if(tx_receipt["status"]):
        print(strftime("%d/%m/%Y %H:%M:%S", gmtime()) + ": tx was executed successfully")
        return True
    else:
        print(strftime("%d/%m/%Y %H:%M:%S", gmtime()) + ": tx failed")
        return False

def WithdrawETH():
    txn = uniswapTokenSwap_router_contract.functions.withdrawETH().buildTransaction({
        'chainId': nodes["chainId"],
        'from': keys["my_account"],
        'nonce': web3.eth.getTransactionCount(keys["my_account"]),
        'value': 0,
        'gas': nodes["gas_limit"],
        'gasPrice': web3.toWei(nodes["gas_price"], 'gwei')})
    signed_tx = web3.eth.account.signTransaction(txn, keys["private_key"])
    tx_hash = web3.eth.sendRawTransaction(signed_tx.rawTransaction)
    print(strftime("%d/%m/%Y %H:%M:%S", gmtime()) + ": " + web3.toHex(tx_hash))
    tx_receipt = web3.eth.waitForTransactionReceipt(tx_hash)
    if(tx_receipt["status"] == 1):
        print(strftime("%d/%m/%Y %H:%M:%S", gmtime()) + ": BNB successfully withdrawn")
        return True
    else:
        print(strftime("%d/%m/%Y %H:%M:%S", gmtime()) + ": BNB withdraw failed")
        return False
def WithdrawToken(token):
    tokenName = str(tokenB_contract.functions.symbol().call())
    tokenBlanace = tokenB_contract.functions.balanceOf(uniswapTokenSwap_contract_address).call()/1e18
    if tokenBlanace > 0:
        print(strftime("%d/%m/%Y %H:%M:%S", gmtime()) + ": Trying to withdraw " + str(tokenBlanace) + " " +str(tokenName))
        txn = uniswapTokenSwap_router_contract.functions.withdrawERC20(Web3.toChecksumAddress(token)).buildTransaction({
            'chainId': nodes["chainId"],
            'from': keys["my_account"],
            'nonce': web3.eth.getTransactionCount(keys["my_account"]),
            'value': 0,
            'gas': nodes["gas_limit"],
            'gasPrice': web3.toWei(nodes["gas_price"], 'gwei')})
        signed_tx = web3.eth.account.signTransaction(txn, keys["private_key"])
        tx_hash = web3.eth.sendRawTransaction(signed_tx.rawTransaction)
        print(strftime("%d/%m/%Y %H:%M:%S", gmtime()) + ": " + web3.toHex(tx_hash))
        tx_receipt = web3.eth.waitForTransactionReceipt(tx_hash)
        if(tx_receipt["status"]):
            print(strftime("%d/%m/%Y %H:%M:%S", gmtime()) + ": " + str(tokenName) + " successfully withdrawn")
            return True
        else:
            print(strftime("%d/%m/%Y %H:%M:%S", gmtime()) + ": " + str(tokenName) + " withdraw failed")
            return False
    else:
        print(strftime("%d/%m/%Y %H:%M:%S", gmtime()) + ": Nothing to withdraw, Token balance is 0")
        return True

def removeTokenBought(token):
    tokenName = str(tokenB_contract.functions.symbol().call())
    txn = uniswapTokenSwap_router_contract.functions.removeProjectBought(Web3.toChecksumAddress(token)).buildTransaction({
        'chainId': nodes["chainId"],
        'from': keys["my_account"],
        'nonce': web3.eth.getTransactionCount(keys["my_account"]),
        'value': 0,
        'gas': nodes["gas_limit"],
        'gasPrice': web3.toWei(nodes["gas_price"], 'gwei')})
    signed_tx = web3.eth.account.signTransaction(txn, keys["private_key"])
    tx_hash = web3.eth.sendRawTransaction(signed_tx.rawTransaction)
    print(strftime("%d/%m/%Y %H:%M:%S", gmtime()) + ": " + web3.toHex(tx_hash))
    tx_receipt = web3.eth.waitForTransactionReceipt(tx_hash)
    if(tx_receipt["status"]):
        print(strftime("%d/%m/%Y %H:%M:%S", gmtime()) + ": " + str(tokenName) + " successfully removed")
        return True
    else:
        print(strftime("%d/%m/%Y %H:%M:%S", gmtime()) + ": Failed to remove " + str(tokenName) + " from Projects list")
        return False
def get_price_tokenB_to_bnb(token):
        return uniswapTokenSwap_router_contract.functions.getEstimatedERC20forETH(Web3.toChecksumAddress(token), int(1e18)).call()
def get_estimate(token, amount):
        return uniswapTokenSwap_router_contract.functions.getEstimatedERC20forETH(Web3.toChecksumAddress(token), int(amount * 1e18)).call()
def get_bought_price(token):
    try:
        projects = uniswapTokenSwap_router_contract.functions.projectsLength().call()
        BUSDPrice = get_price_tokenB_to_bnb(contracts["busd_token"])/1e18
        tokenName = str(tokenB_contract.functions.symbol().call())
        if(projects > 0):
            i = 0
            while i < projects:
                project = uniswapTokenSwap_router_contract.functions.projects(i).call()
                if(str(project[0]) == str(Web3.toChecksumAddress(token))):
                    price = project[1]/project[2]
                    print(strftime("%d/%m/%Y %H:%M:%S", gmtime()) + ": we payed " + str(price/BUSDPrice) + " BUSD/" + str(tokenName))
                    return True
                i += 1
            return False
    except:
        return False
def is_caller(address):
    result = uniswapTokenSwap_router_contract.functions.isApproverCaller(Web3.toChecksumAddress(address)).call()
    if(result):
        return print(strftime("%d/%m/%Y %H:%M:%S", gmtime()) + ": " + str(address) + " is an approved caller")
    else:
        return print(strftime("%d/%m/%Y %H:%M:%S", gmtime()) + ": " + str(address) + " is not an approved caller")
def add_contract_callers():
    addresses = []
    for address in keys["cakeswap"]:
        isApproved = uniswapTokenSwap_router_contract.functions.isApproverCaller(Web3.toChecksumAddress(address["address"])).call()
        if(not isApproved):
            addresses.append(str(Web3.toChecksumAddress(address["address"])))
    txn = uniswapTokenSwap_router_contract.functions.addApproverCallers(addresses).buildTransaction({
        'chainId': nodes["chainId"],
        'from': keys["my_account"],
        'nonce': web3.eth.getTransactionCount(keys["my_account"]),
        'value': 0,
        'gas': nodes["gas_limit"],
        'gasPrice': web3.toWei(nodes["gas_price"], 'gwei')})
    # print(str(addresses))
    # print(str(web3.eth.estimate_gas(txn)))
    # print(str(web3.eth.call(txn)))
    signed_tx = web3.eth.account.signTransaction(txn, keys["private_key"])
    tx_hash = web3.eth.sendRawTransaction(signed_tx.rawTransaction)
    print(strftime("%d/%m/%Y %H:%M:%S", gmtime()) + ": " + web3.toHex(tx_hash))
    tx_receipt = web3.eth.waitForTransactionReceipt(tx_hash)
    if(tx_receipt["status"]):
        print(strftime("%d/%m/%Y %H:%M:%S", gmtime()) + ": Successfully added")
        return True
    else:
        print(strftime("%d/%m/%Y %H:%M:%S", gmtime()) + ": Failed to add addresses to the callers list")
        return False

def buy(tokenB, amount_to_spend, maximum_price):
        tokenName = str(tokenB_contract.functions.symbol().call())
        BUSDPrice = get_price_tokenB_to_bnb(contracts["busd_token"])/1e18
        while True:
            try:
                price = get_price_tokenB_to_bnb(tokenB)
                print(strftime("%d/%m/%Y %H:%M:%S", gmtime()) + ": price = " + str(price/BUSDPrice/1e18) + " BUSD")
            except:
                print(strftime("%d/%m/%Y %H:%M:%S", gmtime()) + ": liquidity pool is not set yet")
                time.sleep(1)
            else:
                while True:
                    BUSDPrice = get_price_tokenB_to_bnb(contracts["busd_token"])/1e18
                    price = get_price_tokenB_to_bnb(tokenB)/1e18
                    # print(strftime("%d/%m/%Y %H:%M:%S", gmtime()) + ": 2- BUSDPrice = " + str(BUSDPrice) + " and 3- price " +str(price))
                    if maximum_price >= price/BUSDPrice:
                        buyToken = SwapETHtoTokenB(tokenB, int(maximum_price * BUSDPrice * 1e18), int(amount_to_spend * 1e18))
                        if(buyToken):
                            print(strftime("%d/%m/%Y %H:%M:%S", gmtime()) + ": sucssufully bought " + str(tokenName))
                            return True
                        else:
                           print(strftime("%d/%m/%Y %H:%M:%S", gmtime()) + ": Something went wrong") 
                           return False
                    else:
                        print(strftime("%d/%m/%Y %H:%M:%S", gmtime()) + ": price is too high, 1 " + str(tokenName) + " = " + str((get_price_tokenB_to_bnb(tokenB)/BUSDPrice)/1e18) + " BUSD")
                    time.sleep(1)
def loop_preparations(i, address):
    txn = uniswapTokenSwap_router_contract.functions.SwapETHtoToken(Web3.toChecksumAddress(transaction_params["token"]), int(transaction_params["amount"]), int(transaction_params["max_price"])).buildTransaction({
        'chainId': nodes["chainId"],
        'from': Web3.toChecksumAddress(address["address"]), 
        'nonce': web3.eth.getTransactionCount(Web3.toChecksumAddress((address["address"]))),
        'value': 0,
        'gas': nodes["gas_limit"],
        'gasPrice': web3.toWei(i, 'gwei')})
    signed_tx = web3.eth.account.signTransaction(txn, address["private_key"])
    raw_transactions.setdefault(i, []).append(signed_tx.rawTransaction)

def prepare_txs(tokenB, amount_to_spend, maximum_price, BUSDPrice):
    transaction_params.update(token = tokenB, amount = amount_to_spend * 1e18, max_price = maximum_price * BUSDPrice * 1e18)
    print(strftime("%d/%m/%Y %H:%M:%S", gmtime()) + ": preparing raw transactions")
    try:
        for i in range(5, 26):
            try:
                pool = Pool(processes=nodes["pool_size"])
                for address in keys["cakeswap"]:
                    pool.apply_async(loop_preparations, (i, address, ), callback=None, error_callback=None)
                pool.close()
                pool.join()
                if(len(raw_transactions[i]) == len(keys["cakeswap"])):
                    print(strftime("%d/%m/%Y %H:%M:%S", gmtime()) + ": succusfully prepared transactions for gwei price: " + str(i))
                else:
                    print(strftime("%d/%m/%Y %H:%M:%S", gmtime()) + ": failed to prepare rawtransactions for all accounts, we are missing: " + str(len(keys["cakeswap"]) - len(raw_transactions[i])) + " accounts")   
                    return False    
            except Exception as e:
                print(strftime("%d/%m/%Y %H:%M:%S", gmtime()) + ": failed with error: " + str(e))
        if(len(raw_transactions) == 21):
            print(strftime("%d/%m/%Y %H:%M:%S", gmtime()) + ": succusfully prepared transactions for gwei prices up to: " + str(i))
            return True
        else: 
            print(strftime("%d/%m/%Y %H:%M:%S", gmtime()) + ": " + str(21 - len(raw_transactions))+ " couldn't be loaded")
            return False
    except Exception as e:
        print(strftime("%d/%m/%Y %H:%M:%S", gmtime()) + ": exception with error: " + str(e))

def buy_loop(txn):
    web3.eth.sendRawTransaction(txn)
    
def buy_strategy(tokenB, amount_to_spend, maximum_price):
    BUSDPrice = get_price_tokenB_to_bnb(contracts["busd_token"])/1e18
    if(prepare_txs(tokenB, amount_to_spend, maximum_price, BUSDPrice)):
        if(mempool(tokenB)[0]):
            print(strftime("%d/%m/%Y %H:%M:%S", gmtime()) + ": detected liquidity in mempool, dev is paying " + str(web3.fromWei(liquidity[0][1], 'gwei')) + " gwei tx: " + str(liquidity[0][2]))
            if(liquidity[0][1] >= web3.toWei(nodes["gas_price"], 'gwei') and liquidity[0][1] <= web3.toWei(nodes["sell_gas_price"], 'gwei')):
                gasPrice = liquidity[0][1]
            else:
                print(strftime("%d/%m/%Y %H:%M:%S", gmtime()) + ": Mission failed! detected liquidity in mempool, but the gasPrice is too high " + str(web3.fromWei(liquidity[0][1], 'gwei')) + " gwei tx: " + str(liquidity[0][2]))
                return False
            pool = Pool(processes=nodes["pool_size"])
            pool.map_async(buy_loop, raw_transactions[int(web3.fromWei(gasPrice, 'gwei'))], callback=None, error_callback=None)
            if(len(remote_nodes) > 0):
                pool.map_async(liquidity_ping, remote_nodes.values(), callback=None, error_callback=None)
            while True:
                try: 
                    txn = uniswapTokenSwap_router_contract.functions.SwapETHtoToken(Web3.toChecksumAddress(tokenB), int(amount_to_spend * 1e18), int(maximum_price * BUSDPrice * 1e18)).buildTransaction({
                        'chainId': nodes["chainId"],
                        'from': Web3.toChecksumAddress(keys["my_account"]), 
                        'nonce': web3.eth.getTransactionCount(Web3.toChecksumAddress((keys["my_account"]))),
                        'value': 0,
                        'gas': nodes["gas_limit"]})
                    simulate_tx = web3.eth.call(txn)
                except Exception as e:
                    if("Price is too high" in str(e)):
                        print(strftime("%d/%m/%Y %H:%M:%S", gmtime()) + ": Mission failed, the price is already too high!")
                        pool.close()
                        pool.join()
                        return False
                    if("token already bought" in str(e)):
                        print(strftime("%d/%m/%Y %H:%M:%S", gmtime()) + ": Succusfully Bought!")
                        pool.close()
                        pool.join()
                        return True
                print(strftime("%d/%m/%Y %H:%M:%S", gmtime()) + ": waiting for the results")
                time.sleep(1)

def buy_bscstarter_loop(bscstarter, address, amount_to_spend):
        try:
            bscstarter_contract_abi = json.loads(contracts["bscstarter_abi"])
            bscstarter_contract_address = Web3.toChecksumAddress(bscstarter)
            bscstarter_contract = web3.eth.contract(address=bscstarter_contract_address, abi=bscstarter_contract_abi)
            account_nonce = web3.eth.getTransactionCount(Web3.toChecksumAddress(address["address"]))
            for i in range (12):
                txn = bscstarter_contract.functions.invest().buildTransaction({
                    'chainId': nodes["chainId"],
                    'from': Web3.toChecksumAddress(address["address"]), 
                    'nonce': account_nonce,
                    'value': int(amount_to_spend * 1e18),
                    'gas': nodes["gas_limit"],
                    'gasPrice': web3.toWei(nodes["bscstarter_gas_price"], 'gwei')})
                account_nonce += 1
                signed_tx = web3.eth.account.signTransaction(txn, address["private_key"])
                tx_hash = web3.eth.sendRawTransaction(signed_tx.rawTransaction)
                print(strftime("%d/%m/%Y %H:%M:%S", gmtime()) + ": txhash " + str(web3.toHex(tx_hash)) + " from address: " + str(address["address"]))
                bscstarter_transactions[address["address"]].append(str(web3.toHex(tx_hash)))
                time.sleep(1)      
        except:
            print(strftime("%d/%m/%Y %H:%M:%S", gmtime()) + ": failed to send tx")
        time.sleep(30)
        try:
            print(strftime("%d/%m/%Y %H:%M:%S", gmtime()) + ": checking pending transactions")
            for i in bscstarter_transactions[address["address"]]:
                gettx = web3.eth.getTransactionReceipt(i)
                if(gettx and gettx["status"] == 1):
                    bscstarter_mission[str(address["address"])] = str(i)
                    print(strftime("%d/%m/%Y %H:%M:%S", gmtime()) + ": account: " + str(address["address"]) + " successfully invested tx: " + str(i))
                    return bscstarter_mission
                else:
                    if(len(bscstarter_transactions[str(address["address"])])> 0):
                        bscstarter_transactions[str(address["address"])].remove(str(i))
                    else:
                        return False 
        except:
            print(strftime("%d/%m/%Y %H:%M:%S", gmtime()) + ": tx is not confirmed yet")

def buy_bscstarter(bscstarter, amount_to_spend, headsteart=0):
    bscstarter_contract_abi = json.loads(contracts["bscstarter_abi"])
    bscstarter_contract_address = Web3.toChecksumAddress(bscstarter)
    bscstarter_contract = web3.eth.contract(address=bscstarter_contract_address, abi=bscstarter_contract_abi)
    try:
        open_time = bscstarter_contract.functions.openTime().call()
        blocktime = web3.eth.get_block('latest')["timestamp"]
    except:
        print(strftime("%d/%m/%Y %H:%M:%S", gmtime()) + ": Open Time is not set yet")
    else:
        while (blocktime + 6 < open_time + (headsteart * 60)):
            pool = Pool(processes=nodes["pool_size"])
            print(strftime("%d/%m/%Y %H:%M:%S", gmtime()) + ": buys open at: "  + strftime("%d/%m/%Y %H:%M:%S", gmtime(open_time)))
            open_time = bscstarter_contract.functions.openTime().call()
            blocktime = web3.eth.get_block('latest')["timestamp"]
            time.sleep(1)
        if(blocktime + 6 >= open_time + (headsteart * 60)):
            print(strftime("%d/%m/%Y %H:%M:%S", gmtime()) + ": trying to buy with "  + str(amount_to_spend) + " BNB on " + str(len(keys["bsc_strater"])) + " addresses")
            for i in keys["bsc_strater"]:
                bscstarter_transactions[str(i["address"])] = []
            for i in keys["bsc_strater"]:
                pool.apply_async(buy_bscstarter_loop, (bscstarter, i, amount_to_spend,  ))
            pool.close()
            pool.join() 
            if(len(bscstarter_mission) > 0 ):
                print(strftime("%d/%m/%Y %H:%M:%S", gmtime()) + ": we have " + str(len(bscstarter_mission)) + " successful buys")
                with open('bscstarter_mission.txt', 'w') as outfile:
                    json.dump(bscstarter_mission, outfile)
                    return True
            else:
                print(strftime("%d/%m/%Y %H:%M:%S", gmtime()) + ": all " + str(len(keys["bsc_strater"])) + " accounts failed to buy")
                return False

def wait_forReceipt(txn, address):
    global claimed
    signed_tx = web3.eth.account.signTransaction(txn, address["private_key"])
    tx_hash = web3.eth.sendRawTransaction(signed_tx.rawTransaction)
    print(strftime("%d/%m/%Y %H:%M:%S", gmtime()) + ": txhash " + str(web3.toHex(tx_hash)) + " from address: " + str(address["address"]))
    tx_receipt = web3.eth.waitForTransactionReceipt(tx_hash)
    if(tx_receipt["status"] == 1):
        print(strftime("%d/%m/%Y %H:%M:%S", gmtime()) + ": Successfully claimed tokens on " + str(address["address"]))
        claimed += 1
    else:
        print(strftime("%d/%m/%Y %H:%M:%S", gmtime()) + ": Failed to claim tokens on " + str(address["address"]))

def bscstarter_send_to_cocontract(token):
    txhash = []
    bep20_contract_abi = json.loads(contracts["bep20_whitelist_abi"])
    tokenB_contract_address = Web3.toChecksumAddress(token)
    tokenB_contract = web3.eth.contract(address=tokenB_contract_address, abi=bep20_contract_abi)
    tokenName = str(tokenB_contract.functions.symbol().call())
    for address in keys["bsc_strater"]:
        tokenBlanace = tokenB_contract.functions.balanceOf(Web3.toChecksumAddress(address["address"])).call()
        if (tokenBlanace > 0):
            txn = tokenB_contract.functions.transfer(Web3.toChecksumAddress(contracts["uniswapTokenSwap"]), tokenBlanace).buildTransaction({
                'chainId': nodes["chainId"],
                'from': Web3.toChecksumAddress(address["address"]),
                'nonce': web3.eth.getTransactionCount(Web3.toChecksumAddress(address["address"])),
                'value': 0,
                'gas': nodes["gas_limit"],
                'gasPrice': web3.toWei(nodes["gas_price"], 'gwei')})
            signed_tx = web3.eth.account.signTransaction(txn, address["private_key"])
            tx_hash = web3.eth.sendRawTransaction(signed_tx.rawTransaction)
            txhash.append(str(web3.toHex(tx_hash)))
            print(strftime("%d/%m/%Y %H:%M:%S", gmtime()) + ": Trying to send " + str(tokenBlanace) + " " + str(tokenName) + " to our contract txhash: " + str(web3.toHex(tx_hash)))
        else:
            print(strftime("%d/%m/%Y %H:%M:%S", gmtime()) + ": Nothing to withdraw, Token balance is 0")
            return False
    time.sleep(30)
    try:
        print(strftime("%d/%m/%Y %H:%M:%S", gmtime()) + ": checking pending transactions")
        for i in txhash:
            gettx = web3.eth.getTransactionReceipt(i)
            if(gettx and gettx["status"] == 1):
                print(strftime("%d/%m/%Y %H:%M:%S", gmtime()) + ": account: " + str(gettx["from"]) + " successfully sent tokens to our contract " + str(i))
            else:
                print(strftime("%d/%m/%Y %H:%M:%S", gmtime()) + ": account: " + str(gettx["from"]) + " failed to send tokens to our contract " + str(i))
    except:
        print(strftime("%d/%m/%Y %H:%M:%S", gmtime()) + ": tx is not confirmed yet")

def fund_accounts(amount):
    txhash = []
    addresses = len(keys["cakeswap"])
    accountBalance = web3.eth.get_balance(Web3.toChecksumAddress(keys["my_account"]))/1e18
    account_nonce = web3.eth.get_transaction_count(Web3.toChecksumAddress(keys["my_account"]))
    if (accountBalance > (addresses * amount)):
        for address in keys["cakeswap"]:
            addressBalance = web3.eth.get_balance(Web3.toChecksumAddress(address["address"]))/1e18
            if(addressBalance < amount):
                try:
                    txn = dict(
                        nonce = account_nonce,
                        gasPrice = web3.toWei(nodes["gas_price"], 'gwei'),
                        gas = 21000,
                        to = str(Web3.toChecksumAddress(address["address"])),
                        value = int((amount - addressBalance)  * 1e18),
                        data=b'',)
                    signed_tx = web3.eth.account.signTransaction(txn, keys["private_key"])
                    tx_hash = web3.eth.sendRawTransaction(signed_tx.rawTransaction)
                    account_nonce += 1 
                    txhash.append(str(web3.toHex(tx_hash)))
                    print(strftime("%d/%m/%Y %H:%M:%S", gmtime()) + ": Trying to send " + str(amount) + " BNB to " + address["address"] + " txhash: " + str(web3.toHex(tx_hash))) 
                except Exception as e:
                    print(strftime("%d/%m/%Y %H:%M:%S", gmtime()) + ": failed to fund " + str(address["address"]) + " " + str(e))
            else:
                print(strftime("%d/%m/%Y %H:%M:%S", gmtime()) + ": " + str(address["address"]) + " doesn't need funcing")
    else:
        print(strftime("%d/%m/%Y %H:%M:%S", gmtime()) + ": not enough funds to fund " + str(addresses) + " with " + amount)
    if(len(txhash) > 0):
        print(strftime("%d/%m/%Y %H:%M:%S", gmtime()) + ": waiting 30 secs for transactions to be confirmed")
        time.sleep(30)
        print(strftime("%d/%m/%Y %H:%M:%S", gmtime()) + ": checking pending transactions")
        for i in txhash:
            try: 
                gettx = web3.eth.getTransactionReceipt(i)
                if(gettx and gettx["status"] == 1):
                    print(strftime("%d/%m/%Y %H:%M:%S", gmtime()) + ": successfully funded " + str(gettx["to"]))
                else:
                    print(strftime("%d/%m/%Y %H:%M:%S", gmtime()) + ": failed to fund " + str(gettx["to"]))
            except:
                print(strftime("%d/%m/%Y %H:%M:%S", gmtime()) + ": tx is not confirmed yet")

def withdraw_toadmin_bscstarter():
    txhash = []
    for address in keys["bsc_strater"]:
        addressBalance = web3.eth.get_balance(Web3.toChecksumAddress(address["address"]))
        if (addressBalance - (web3.toWei(nodes["gas_price"], 'gwei') * 21000) > 0):
            txn = dict(
                chainId = nodes["chainId"],
                nonce = web3.eth.get_transaction_count(Web3.toChecksumAddress(address["address"])),
                gasPrice = web3.toWei(nodes["gas_price"], 'gwei'),
                gas = 21000,
                to = str(Web3.toChecksumAddress(keys["my_account"])),
                value = int(addressBalance  - (web3.toWei(nodes["gas_price"], 'gwei') * 21000)),
                data=b'',)
            signed_tx = web3.eth.account.signTransaction(txn, address["private_key"])
            tx_hash = web3.eth.sendRawTransaction(signed_tx.rawTransaction)
            txhash.append(str(web3.toHex(tx_hash)))
            print(strftime("%d/%m/%Y %H:%M:%S", gmtime()) + ": Trying to send " + str(addressBalance/1e18) + " BNB to our contract txhash: " + str(web3.toHex(tx_hash)))   
        else:
            print(strftime("%d/%m/%Y %H:%M:%S", gmtime()) + ": Nothing to withdraw, address balance is 0")
    if(len(txhash) > 0):
        print(strftime("%d/%m/%Y %H:%M:%S", gmtime()) + ": waiting 30 secs for transactions to be confirmed")
        time.sleep(30)
        try:
            print(strftime("%d/%m/%Y %H:%M:%S", gmtime()) + ": checking pending transactions")
            for i in txhash:
                gettx = web3.eth.waitForTransactionReceipt(i)
                if(gettx and gettx["status"] == 1):
                    print(strftime("%d/%m/%Y %H:%M:%S", gmtime()) + ": account: "  + str(gettx["from"]) + " successfully withdraw BNB to our admin address " + str(i))
                else:
                    print(strftime("%d/%m/%Y %H:%M:%S", gmtime()) + ": account: " + str(gettx["from"]) + " failed to withdraw BNB to our admin address " + str(i))
        except:
            print(strftime("%d/%m/%Y %H:%M:%S", gmtime()) + ": something went wrong")
    else:
        print(strftime("%d/%m/%Y %H:%M:%S", gmtime()) + ": nothing to withdraw in " + str(len(keys["bsc_strater"])) + " addresses")
def withdraw_toadmin():
    txhash = []
    for address in keys["cakeswap"]:
        addressBalance = web3.eth.get_balance(Web3.toChecksumAddress(address["address"]))
        if (addressBalance - (web3.toWei(nodes["gas_price"], 'gwei') * 21000) > 0):
            txn = dict(
                chainId = nodes["chainId"],
                nonce = web3.eth.get_transaction_count(Web3.toChecksumAddress(address["address"])),
                gasPrice = web3.toWei(nodes["gas_price"], 'gwei'),
                gas = 21000,
                to = str(Web3.toChecksumAddress(keys["my_account"])),
                value = int(addressBalance  - (web3.toWei(nodes["gas_price"], 'gwei') * 21000)),
                data=b'',)
            signed_tx = web3.eth.account.signTransaction(txn, address["private_key"])
            tx_hash = web3.eth.sendRawTransaction(signed_tx.rawTransaction)
            txhash.append(str(web3.toHex(tx_hash)))
            print(strftime("%d/%m/%Y %H:%M:%S", gmtime()) + ": Trying to send " + str(addressBalance/1e18) + " BNB to our contract txhash: " + str(web3.toHex(tx_hash)))   
        else:
            print(strftime("%d/%m/%Y %H:%M:%S", gmtime()) + ": Nothing to withdraw, Token balance is 0")
    if(len(txhash) > 0):
        print(strftime("%d/%m/%Y %H:%M:%S", gmtime()) + ": waiting 60 secs for transactions to be confirmed")
        time.sleep(60)
        try:
            print(strftime("%d/%m/%Y %H:%M:%S", gmtime()) + ": checking pending transactions")
            for i in txhash:
                gettx = web3.eth.waitForTransactionReceipt(i)
                if(gettx and gettx["status"] == 1):
                    print(strftime("%d/%m/%Y %H:%M:%S", gmtime()) + ": account: "  + str(gettx["from"]) + " successfully sent tokens to our contract " + str(i))
                else:
                    print(strftime("%d/%m/%Y %H:%M:%S", gmtime()) + ": account: " + str(gettx["from"]) + " failed to send tokens to our contract " + str(i))
        except:
            print(strftime("%d/%m/%Y %H:%M:%S", gmtime()) + ": tx is not confirmed yet")
    else:
        print(strftime("%d/%m/%Y %H:%M:%S", gmtime()) + ": nothing to withdraw in " + str(len(keys["cakeswap"])) + " addresses")

def claim_bscstarter(bscstarter):
    pool = Pool(processes=nodes["pool_size"])
    bscstarter_contract_abi = json.loads(contracts["bscstarter_abi"])
    bscstarter_contract_address = Web3.toChecksumAddress(bscstarter)
    bscstarter_contract = web3.eth.contract(address=bscstarter_contract_address, abi=bscstarter_contract_abi)
    while True:
        cakeLiq = bscstarter_contract.functions.cakeLiquidityAdded().call()
        if(cakeLiq):
            if os.path.isfile('bscstarter_mission.txt') and os.access('bscstarter_mission.txt', os.R_OK):
                with open('bscstarter_mission.txt') as json_file:
                    accounts = json.loads(json_file.read())
                    for address in keys["bsc_strater"]:
                        if (str(address["address"]) in accounts):
                            account_nonce = web3.eth.getTransactionCount(Web3.toChecksumAddress(str(address["address"])))
                            txn = bscstarter_contract.functions.claimTokens().buildTransaction({
                                'chainId': nodes["chainId"],
                                'from': Web3.toChecksumAddress(str(address["address"])), 
                                'nonce': account_nonce,
                                'value': 0,
                                'gas': nodes["gas_limit"],
                                'gasPrice': web3.toWei(nodes["gas_price"], 'gwei')})
                            pool.apply_async(wait_forReceipt, (txn, address,  ))
                    pool.close()
                    pool.join()
                    time.sleep(30)
                    if(claimed == len(accounts) or claimed > 0):
                        print(strftime("%d/%m/%Y %H:%M:%S", gmtime()) + ": Successfully claimed tokens " + str(claimed) + " accounts")   
                        return True
                    else:
                        print(strftime("%d/%m/%Y %H:%M:%S", gmtime()) + ": failed to claim tokens")
                        return False
            else:
                print(strftime("%d/%m/%Y %H:%M:%S", gmtime()) + ": nothing to claim bscstarter_mission doesn't exist")
                return False
        else:
            print(strftime("%d/%m/%Y %H:%M:%S", gmtime()) + ": can't claim now, liquidity still not added on pancakeswap")
        time.sleep(3) 
def sell_strategy(tokenB, amount_to_sell, minimum_price):
        tokenName = str(tokenB_contract.functions.symbol().call())
        while True:
            BUSDPrice = get_price_tokenB_to_bnb(contracts["busd_token"])/1e18
            price = get_price_tokenB_to_bnb(tokenB)
            print(strftime("%d/%m/%Y %H:%M:%S", gmtime()) + ": one " + str(tokenName) + " is worth: " + str((price/BUSDPrice)/1e18) + " BUSD")
            if price >= minimum_price * BUSDPrice * 1e18 :
                tokenBlanace = tokenB_contract.functions.balanceOf(uniswapTokenSwap_contract_address).call()
                print(strftime("%d/%m/%Y %H:%M:%S", gmtime()) + ": we have " + str(tokenBlanace/1e18) + " " + str(tokenName) + ", we are trying to sell " + str(amount_to_sell/1e18) + " " + str(tokenName))
                sellToken = swapERC20toETH(tokenB, int(amount_to_sell))
                if(sellToken):
                    print(strftime("%d/%m/%Y %H:%M:%S", gmtime()) + ": Succusfully sold: " + str(amount_to_sell/1e18) + " " + str(tokenName))
                    return True
                else:
                    return False
            else:
                print(strftime("%d/%m/%Y %H:%M:%S", gmtime()) + ": skipping current price of: " + str((price/BUSDPrice)/1e18 ) + " BUSD is low")
            time.sleep(6)
def sell(tokenB, amount_to_sell, minimum_price):
        tokenName = str(tokenB_contract.functions.symbol().call())
        while True:
            BUSDPrice = get_price_tokenB_to_bnb(contracts["busd_token"])/1e18
            price = get_price_tokenB_to_bnb(tokenB)
            print(strftime("%d/%m/%Y %H:%M:%S", gmtime()) + ": one " + str(tokenName) + " is worth: " + str((price/BUSDPrice)/1e18) + " BUSD")
            if price >= minimum_price * BUSDPrice * 1e18 :
                tokenBlanace = tokenB_contract.functions.balanceOf(uniswapTokenSwap_contract_address).call()
                if amount_to_sell < 100:
                    amountToSell = (tokenBlanace * amount_to_sell) / 100
                else:
                    amountToSell = tokenBlanace
                print(strftime("%d/%m/%Y %H:%M:%S", gmtime()) + ": we have " + str(tokenBlanace/1e18) + " " + str(tokenName) + ", we are trying to sell " + str(amountToSell/1e18) + " " + str(tokenName))
                sellToken = swapERC20toETH(tokenB, int(amountToSell))
                if(sellToken):
                    print(strftime("%d/%m/%Y %H:%M:%S", gmtime()) + ": Succusfully sold: " + str(amountToSell/1e18) + " " + str(tokenName))
                    return True
                else:
                    return False
            else:
                print(strftime("%d/%m/%Y %H:%M:%S", gmtime()) + ": skipping current price of: " + str((price/BUSDPrice)/1e18 ) + " BUSD is low")
            time.sleep(3)

def main(arg1):
    if(str(arg1) == "help"):
        print(str(help))
    elif(str(arg1) == "withdraw_toadmin_bscstarter"):
        try:
            withdraw_toadmin_bscstarter()
        except Exception as e:
            print(strftime("%d/%m/%Y %H:%M:%S", gmtime()) + ": something went wrong " + str(e))
    elif(str(arg1) == "withdraw_toadmin"):
        try:
            withdraw_toadmin()
        except Exception as e:
            print(strftime("%d/%m/%Y %H:%M:%S", gmtime()) + ": something went wrong " + str(e))
    elif(str(arg1) == "fund_accounts"):
        try:
            amount = str(sys.argv[2])
        except:
            print(strftime("%d/%m/%Y %H:%M:%S", gmtime()) + ": please enter the funding amount")
        else:
            fund_accounts(float(amount))
    elif(str(arg1) == "createaccounts"):
        try:
            number = int(sys.argv[2])
        except:
            print(strftime("%d/%m/%Y %H:%M:%S", gmtime()) + ": please provide the number of key pairs to be generated")
        else:
            generate_accounts(number)
    elif(str(arg1) == "mempool"):
        try:
            tokenB = str(sys.argv[2])
            if(not Web3.isAddress(tokenB)):
                raise Exception("please provide a valid contract address")
            else:
                tokenB = Web3.toChecksumAddress(tokenB)
        except Exception as e:
            print(strftime("%d/%m/%Y %H:%M:%S", gmtime()) + ": " + str(e))
        else:
            if(mempool(tokenB)[0]):
                print(str(strftime("%d/%m/%Y %H:%M:%S", gmtime()) + ": " + str(liquidity[0])))
    elif(str(arg1) == "iscaller"):
        try:
            address = str(sys.argv[2])
            if(not Web3.isAddress(address)):
                raise Exception("please provide a valid address")
            else:
                address = Web3.toChecksumAddress(address)
        except Exception as e:
            print(strftime("%d/%m/%Y %H:%M:%S", gmtime()) + ": " + str(e))
        else:
            is_caller(address)
    elif(str(arg1) == "addcallers"):
        try:
            add_contract_callers()
        except Exception as e:
            print(strftime("%d/%m/%Y %H:%M:%S", gmtime()) + ": something went wrong " + str(e))
    elif(str(arg1) == "gettx"):
        try:
            tx = str(sys.argv[2])
        except:
            print(strftime("%d/%m/%Y %H:%M:%S", gmtime()) + ": please provide the tx hash")
        else:
            print(strftime("%d/%m/%Y %H:%M:%S", gmtime()) + ": " + str(web3.eth.get_transaction(tx)))
    elif(str(arg1) == "getestimate"):
        try:
            tokenB = str(sys.argv[2])
            amount = float(sys.argv[3])
            if(not Web3.isAddress(tokenB)):
                raise Exception("Please provide Token contract address and amount")
            else:
                tokenB = Web3.toChecksumAddress(tokenB)
        except Exception as e:
            print(strftime("%d/%m/%Y %H:%M:%S", gmtime()) + ": " + str(e))
        else:
            print(strftime("%d/%m/%Y %H:%M:%S", gmtime()) + ": " + str(get_estimate(tokenB, amount)/1e18) + " BNB" )
    elif(str(arg1) == "gettxreceipt"):
        try:
            tx = str(sys.argv[2])
        except:
            print(strftime("%d/%m/%Y %H:%M:%S", gmtime()) + ": please provide the tx hash")
        else:
            print(strftime("%d/%m/%Y %H:%M:%S", gmtime()) + ": " + str(web3.eth.getTransactionReceipt(tx)))
    elif(str(arg1) == "bought"):
        try:
            tokenB = str(sys.argv[2])
        except:
            print(strftime("%d/%m/%Y %H:%M:%S", gmtime()) + ": Please provide Token contract address")
        else:
            if(not get_bought_price(tokenB)):
                print(strftime("%d/%m/%Y %H:%M:%S", gmtime()) + ": We didn't buy this token yet!")
    elif(str(arg1) == "buy"):
        try:
            tokenB = str(sys.argv[2])
            amount_to_spend = float(sys.argv[3])
            maximum_price = float(sys.argv[4])
            if(not Web3.isAddress(tokenB)):
                raise Exception("Please provide correct contract address")
            else:
                tokenB = Web3.toChecksumAddress(tokenB)
        except Exception as e:
            print(strftime("%d/%m/%Y %H:%M:%S", gmtime()) + ": please insert all variables needed in this order (without comma): Token_contrat amount_to_spend maximum_price " + str(e))
        else:
            buy(tokenB, amount_to_spend, maximum_price)
    elif(str(arg1) == "buy_strategy"):
        try:
            tokenB = str(sys.argv[2])
            amount_to_spend = float(sys.argv[3])
            maximum_price = float(sys.argv[4])
            if(not Web3.isAddress(tokenB)):
                raise Exception("Please provide correct contract address")
            else:
                tokenB = Web3.toChecksumAddress(tokenB)
        except Exception as e:
            print(strftime("%d/%m/%Y %H:%M:%S", gmtime()) + ": please insert all variables needed in this order (without comma): Token_contrat amount_to_spend maximum_price " + str(e))
        else:
            buy_strategy(tokenB, amount_to_spend, maximum_price)
    elif(str(arg1) == "sell"):
        try:
            tokenB = str(sys.argv[2])
            amount_to_sell = float(sys.argv[3])
            minimum_price = float(sys.argv[4])
            maximum_price = float(sys.argv[4])
            if(not Web3.isAddress(tokenB)):
                raise Exception("Please provide correct contract address")
            else:
                tokenB = Web3.toChecksumAddress(tokenB)
        except Exception as e:
            print(strftime("%d/%m/%Y %H:%M:%S", gmtime()) + ": please insert all variables needed in this order (without comma): Token_contrat amount_to_sell minimum_price " + str(e))
        else:
            sell(tokenB, amount_to_sell, minimum_price)
    elif(str(arg1) == "getprice"):
        try:
            tokenB = str(sys.argv[2])
            if(not Web3.isAddress(tokenB)):
                raise Exception("Please provide correct contract address")
            else:
                tokenB = Web3.toChecksumAddress(tokenB)
        except:
            print(strftime("%d/%m/%Y %H:%M:%S", gmtime()) + ": please provide Token contract address")
        else:
            BUSDPrice = get_price_tokenB_to_bnb(Web3.toChecksumAddress(contracts["busd_token"]))/1e18
            if(str(tokenB) == str(contracts["busd_token"])):
                print(strftime("%d/%m/%Y %H:%M:%S", gmtime()) + ": 1 " + str(tokenB_contract.functions.symbol().call()) + " is worth: 1 BUSD ")
            elif(str(tokenB) == str(contracts["wbnb_token"])):
                print(strftime("%d/%m/%Y %H:%M:%S", gmtime()) + ": one " + str(tokenB_contract.functions.symbol().call()) + " is worth: " + str(1 / BUSDPrice) + " BUSD ")
            else:
                print(strftime("%d/%m/%Y %H:%M:%S", gmtime()) + ": one " + str(tokenB_contract.functions.symbol().call()) + " is worth: " + str(((get_price_tokenB_to_bnb(tokenB)/1e18) / BUSDPrice)) + " BUSD ")
    elif(str(arg1) == "remove"):
        try:
            tokenB = str(sys.argv[2])
            if(not Web3.isAddress(tokenB)):
                raise Exception("Please provide correct contract address")
            else:
                tokenB = Web3.toChecksumAddress(tokenB)
        except Exception as e:
            print(strftime("%d/%m/%Y %H:%M:%S", gmtime()) + ": please provide Token contract address " + str(e))
        else: 
            removeTokenBought(tokenB)
    elif(str(arg1) == "withdraw"):
        try:
            tokenB = str(sys.argv[2])
            if(not Web3.isAddress(tokenB)):
                raise Exception("Please provide correct contract address")
            else:
                tokenB = Web3.toChecksumAddress(tokenB)
            tokenBlanace = tokenB_contract.functions.balanceOf(uniswapTokenSwap_contract_address).call()
            addressBalance = web3.eth.get_balance(uniswapTokenSwap_contract_address)
        except Exception as e:
            print(strftime("%d/%m/%Y %H:%M:%S", gmtime()) + ": please provide Token contract address " + str(e))
        else:
            if tokenBlanace > 0:
                WithdrawToken(tokenB)
            if addressBalance > 0:
                WithdrawETH()
    elif(str(arg1) == "buy_bscstarter"):
        try:
            bscstarter = str(sys.argv[2])
            if(not Web3.isAddress(bscstarter)):
                raise Exception("Please provide correct contract address")
            else:
                bscstarter = Web3.toChecksumAddress(bscstarter)
            amount_to_spend = float(sys.argv[3])
            headsteart =  float(sys.argv[4])
        except Exception as e:
            print(strftime("%d/%m/%Y %H:%M:%S", gmtime()) + ": please insert all variables needed in this order (without comma): bscstarter_contract amount_to_spend headstart in minutes " + str(e))
        else:
            buy_bscstarter(bscstarter, amount_to_spend, headsteart)
    elif(str(arg1) == "claim_bscstarter"):
        try:
            bscstarter = str(sys.argv[2])
            if(not Web3.isAddress(bscstarter)):
                raise Exception("Please provide correct contract address")
            else:
                bscstarter = Web3.toChecksumAddress(bscstarter)
        except Exception as e:
            print(strftime("%d/%m/%Y %H:%M:%S", gmtime()) + ": please insert all variables needed: bscstarter_contract " + str(e))
        else:
            claim_bscstarter(Web3.toChecksumAddress(bscstarter))
    elif(str(arg1) == "bscstarter_send_to_cocontract"):
        try:
            tokenB = str(sys.argv[2])
            if(not Web3.isAddress(tokenB)):
                raise Exception("Please provide correct contract address")
            else:
                tokenB = Web3.toChecksumAddress(tokenB)
        except Exception as e:
            print(strftime("%d/%m/%Y %H:%M:%S", gmtime()) + ": please insert all variables needed: token contract " + str(e))
        else:
            bscstarter_send_to_cocontract(tokenB)
    elif(str(arg1) == "strategy"):
        try:
            tokenB = str(sys.argv[2])
            if(not Web3.isAddress(tokenB)):
                raise Exception("Please provide correct contract address")
            else:
                tokenB = Web3.toChecksumAddress(tokenB)
            amount_to_spend = float(sys.argv[3])
            maximum_buy_price = float(sys.argv[4])
            minimum_sell_price = float(sys.argv[5])
            sell_pecentage = float(sys.argv[6])
        except Exception as e:
            print(strftime("%d/%m/%Y %H:%M:%S", gmtime()) + ": please insert all variables needed in this order (without comma): Token_contrat amount_to_spend maximum_buy_price minimum_sell_price sell_pecentage " + str(e))
        else:
            maximum_price = maximum_buy_price
            minimum_price = minimum_sell_price
            if(buy_strategy(tokenB, amount_to_spend, maximum_price)):
                print(strftime("%d/%m/%Y %H:%M:%S", gmtime()) + ": witing 30 secs for more buys to come in")
                time.sleep(30)
                percentage = 0
                tokenBlanace = tokenB_contract.functions.balanceOf(uniswapTokenSwap_contract_address).call()/1e18
                if sell_pecentage < 100:
                    amount = (((tokenBlanace * sell_pecentage * 100)/10000) * 1e18 ) - 100
                    while (percentage < 100):
                        if(sell_strategy(tokenB, amount, minimum_price)):
                            print(strftime("%d/%m/%Y %H:%M:%S", gmtime()) + ": successfully sold " + str(sell_pecentage) + "%")
                            percentage += sell_pecentage
                            if percentage == 100:
                                print(strftime("%d/%m/%Y %H:%M:%S", gmtime()) + ": Strategy executed successfully")
                                return True
                        else:
                            print(strftime("%d/%m/%Y %H:%M:%S", gmtime()) + ": sell failed trying one more time")
                        time.sleep(60)
                else:
                    amount = tokenBlanace
                    while True:
                        if(sell_strategy(tokenB, amount, minimum_price)):
                                print(strftime("%d/%m/%Y %H:%M:%S", gmtime()) + ": successfully sold " + str(sell_pecentage) + "%")
                        else:
                            print(strftime("%d/%m/%Y %H:%M:%S", gmtime()) + ": sell failed trying one more time")
    elif(str(arg1) == "strategy_bscstarter_liquidity"):
        try:
            tokenB = str(sys.argv[2])
            bscstarter = str(sys.argv[3])
            if(not Web3.isAddress(tokenB) and not Web3.isAddress(bscstarter)):
                raise Exception("Please provide correct contract addresses")
            else:
                tokenB = Web3.toChecksumAddress(tokenB)
                bscstarter = Web3.toChecksumAddress(bscstarter)
            amount_to_spend = float(sys.argv[4])
            maximum_buy_price = float(sys.argv[5])
            minimum_sell_price = float(sys.argv[6])
            sell_pecentage = float(sys.argv[7])
        except Exception as e:
            print(strftime("%d/%m/%Y %H:%M:%S", gmtime()) + ": please insert all variables needed in this order (without comma): token_contrat bscstarter_contract amount_to_spend maximum_buy_price minimum_sell_price sell_pecentage " + str(e))
        else:
            maximum_price = maximum_buy_price
            minimum_price = minimum_sell_price
            if(buy_strategy(tokenB, amount_to_spend, maximum_price)):
                print(strftime("%d/%m/%Y %H:%M:%S", gmtime()) + ": witing 30 secs for more buys to come in")
                time.sleep(30)
                percentage = 0
                tokenBlanace = tokenB_contract.functions.balanceOf(uniswapTokenSwap_contract_address).call()/1e18
                if sell_pecentage < 100:
                    amount = (((tokenBlanace * sell_pecentage * 100)/10000) * 1e18 ) - 100
                    while (percentage < 100):
                        if(sell_strategy(tokenB, amount, minimum_price)):
                            print(strftime("%d/%m/%Y %H:%M:%S", gmtime()) + ": successfully sold " + str(sell_pecentage) + "%")
                            percentage += sell_pecentage
                            if percentage == 100:
                                print(strftime("%d/%m/%Y %H:%M:%S", gmtime()) + ": Strategy executed successfully")
                                return True
                        else:
                            print(strftime("%d/%m/%Y %H:%M:%S", gmtime()) + ": sell failed trying one more time")
                        time.sleep(60)
                else:
                    amount = tokenBlanace
                    while True:
                        if(sell_strategy(tokenB, amount, minimum_price)):
                                print(strftime("%d/%m/%Y %H:%M:%S", gmtime()) + ": successfully sold " + str(sell_pecentage) + "%")
                        else:
                            print(strftime("%d/%m/%Y %H:%M:%S", gmtime()) + ": sell failed trying one more time")
    elif(str(arg1) == "strategy_bscstarter"):
        try:
            tokenB = str(sys.argv[2])
            bscstarter = str(sys.argv[3])
            if(not Web3.isAddress(tokenB) and not Web3.isAddress(bscstarter)):
                raise Exception("Please provide correct contract addresses")
            else:
                tokenB = Web3.toChecksumAddress(tokenB)
                bscstarter = Web3.toChecksumAddress(bscstarter)
            amount_to_spend = float(sys.argv[4])
            minimum_price = float(sys.argv[5])
            sell_pecentage = float(sys.argv[6])
            if(len(sys.argv)> 7):
                headsteart =  float(sys.argv[7])
            else:
                headsteart = 0
        except Exception as e:
            print(strftime("%d/%m/%Y %H:%M:%S", gmtime()) + ": please insert all variables needed in this order (without comma): token_contrat bscstarter_contract amount_to_spend minimum_sell_price sell_pecentage headsteart(optional) " + str(e))
        else:
            if(buy_bscstarter(bscstarter, amount_to_spend, headsteart)):
                if(claim_bscstarter(bscstarter)):
                    if(bscstarter_send_to_cocontract(tokenB)):
                        percentage = 0
                        tokenBlanace = tokenB_contract.functions.balanceOf(uniswapTokenSwap_contract_address).call()/1e18
                        if tokenBlanace > 0:
                            if sell_pecentage < 100:
                                amount = (((tokenBlanace * sell_pecentage * 100)/10000) * 1e18 ) - 100
                                while (percentage < 100):
                                    if(sell_strategy(tokenB, amount, minimum_price)):
                                        print(strftime("%d/%m/%Y %H:%M:%S", gmtime()) + ": successfully sold " + str(sell_pecentage) + " %")
                                        percentage += sell_pecentage
                                        if percentage == 100:
                                            print(strftime("%d/%m/%Y %H:%M:%S", gmtime()) + ": Strategy executed successfully")
                                            return True
                                    else:
                                        print(strftime("%d/%m/%Y %H:%M:%S", gmtime()) + ": sell failed trying one more time")
                                    time.sleep(15)
                            else:
                                while True:
                                    if(sell(tokenB, 100, minimum_price)):
                                            print(strftime("%d/%m/%Y %H:%M:%S", gmtime()) + ": successfully sold " + str(sell_pecentage) + " %")
                                    else:
                                        print(strftime("%d/%m/%Y %H:%M:%S", gmtime()) + ": sell failed trying one more time")
                                    time.sleep(10)
                        else:
                            print(strftime("%d/%m/%Y %H:%M:%S", gmtime()) + ": token balance is 0 nothing to sell")  
                    else:
                        print(strftime("%d/%m/%Y %H:%M:%S", gmtime()) + ": failed to send the tokens to our contract") 
                else:        
                    print(strftime("%d/%m/%Y %H:%M:%S", gmtime()) + ": failed to claim tokens") 
            else:
                print(strftime("%d/%m/%Y %H:%M:%S", gmtime()) + ": failed to buy any tokens") 

    elif(str(arg1) == "strategy_ww"):
        try:
            tokenB = str(sys.argv[2])
            if(not Web3.isAddress(tokenB)):
                raise Exception("Please provide correct contract address")
            else:
                tokenB = Web3.toChecksumAddress(tokenB)
            amount_to_spend = float(sys.argv[3])
            maximum_buy_price = float(sys.argv[4])
            minimum_sell_price = float(sys.argv[5])
            sell_pecentage = float(sys.argv[6])
            delay = float(sys.argv[7])
            whiteList = tokenB_contract.functions._lgeTimestamp().call()
        except Exception as e:
            print(strftime("%d/%m/%Y %H:%M:%S", gmtime()) + ": please insert all variables needed in this order (without comma): Token_contrat amount_to_spend maximum_buy_price minimum_sell_price sell_pecentage delay " + str(e))
        else:
            while True:
                whiteList = tokenB_contract.functions._lgeTimestamp().call()
                blocktime = web3.eth.get_block('latest')["timestamp"]
                if(whiteList != 0 and (whiteList + (delay * 60) - 10) >= blocktime):
                    maximum_price = maximum_buy_price
                    minimum_price = minimum_sell_price
                    if(buy_strategy(tokenB, amount_to_spend, maximum_price)):
                        time.sleep(60)
                        percentage = 0
                        tokenBlanace = tokenB_contract.functions.balanceOf(uniswapTokenSwap_contract_address).call() - 100
                        if sell_pecentage < 100:
                            amount = (tokenBlanace * sell_pecentage * 100)/10000
                            while (percentage < 100):
                                if(sell_strategy(tokenB, amount, minimum_price)):
                                    print(strftime("%d/%m/%Y %H:%M:%S", gmtime()) + ": successfully sold " + str(sell_pecentage) + "%")
                                    percentage += sell_pecentage
                                    if percentage == 100:
                                        print(strftime("%d/%m/%Y %H:%M:%S", gmtime()) + ": Strategy executed successfully")
                                        return True
                                else:
                                    print(strftime("%d/%m/%Y %H:%M:%S", gmtime()) + ": sell failed trying one more time")
                                time.sleep(60)
                        else:
                            amount = tokenBlanace
                            while True:
                                if(sell_strategy(tokenB, amount, minimum_price)):
                                        print(strftime("%d/%m/%Y %H:%M:%S", gmtime()) + ": successfully sold " + str(sell_pecentage) + "%")
                                else:
                                    print(strftime("%d/%m/%Y %H:%M:%S", gmtime()) + ": sell failed trying one more time")
                if(whiteList == 0):
                    print(strftime("%d/%m/%Y %H:%M:%S", gmtime()) + ": bot prevention time is not set yet")
                else:
                    print(strftime("%d/%m/%Y %H:%M:%S", gmtime()) + ": bot prevention is still on until: " + strftime("%H:%M:%S", gmtime(whiteList + (delay * 60))))
                time.sleep(1)

if(len(sys.argv) > 1 and str(sys.argv[1]) in arguments):
    if(len(sys.argv) > 2):
        if(str(sys.argv[1]) in arguments):
            if(sys.argv[1] in token_arguments):
                if(Web3.isAddress(str(sys.argv[2]))):
                    tokenB = str(sys.argv[2])
                    if(not Web3.isAddress(tokenB)):
                        raise Exception("Please provide correct contract address")
                    else:
                        tokenB = Web3.toChecksumAddress(tokenB)
                    bep20_contract_abi = json.loads(contracts["bep20_whitelist_abi"])
                    tokenB_contract_address = Web3.toChecksumAddress(tokenB)
                    tokenB_contract = web3.eth.contract(address=tokenB_contract_address, abi=bep20_contract_abi)
                else:
                    print(strftime("%d/%m/%Y %H:%M:%S", gmtime()) + ": please provide the contract address")
        else:
            print(strftime("%d/%m/%Y %H:%M:%S", gmtime()) + ": these are the available functions: " + str(help))
    main(sys.argv[1])     
else:
    print(strftime("%d/%m/%Y %H:%M:%S", gmtime()) + ": these are the available functions: " + str(help))


if __name__ == '__main__':
    main(sys.argv)
