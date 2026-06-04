from dotenv import load_dotenv
from web3 import Web3
import json, os

load_dotenv()

# Test connexion Ganache
w3 = Web3(Web3.HTTPProvider(os.getenv("RPC_URL")))
print("Connecté :", w3.is_connected())
print("Chain ID  :", w3.eth.chain_id)
print("Bloc actuel :", w3.eth.block_number)

# Test lecture solde admin
admin = os.getenv("ADMIN_ADDRESS")
solde = w3.eth.get_balance(admin)
print("Solde ETH :", w3.from_wei(solde, 'ether'), "ETH")

# Test lecture contrat FintechToken
with open("abi/FintechToken.json") as f:
    abi = json.load(f)

token = w3.eth.contract(
    address=Web3.to_checksum_address(os.getenv("TOKEN_ADDRESS")),
    abi=abi
)

nom     = token.functions.name().call()
symbole = token.functions.symbol().call()
supply  = token.functions.totalSupply().call() / 10**18

print(f"\nToken    : {nom} ({symbole})")
print(f"Supply   : {supply:,.0f} FTK")
print(f"Solde admin : {token.functions.balanceOf(admin).call() / 10**18:,.0f} FTK")

print("\n Tout fonctionne — prêt pour le dashboard Flask !")