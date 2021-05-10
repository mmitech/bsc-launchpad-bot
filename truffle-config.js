// const path = require("path");
const HDWalletProvider = require("@truffle/hdwallet-provider")
require("dotenv").config()

module.exports = {
	// See <http://truffleframework.com/docs/advanced/configuration> to customize your Truffle configuration!
	// contracts_build_directory: path.join(__dirname, "client/src/contracts"),
	networks: {
	//   bscankr: {
	//     provider: new HDWalletProvider(process.env.ACCOUNT_KEY, "https://" + process.env.ANKR_USER + ":" + process.env.ANKR_PASS + process.env.ARKN_APP_API),
	//     network_id: 56,
	//     gas: 3000000,
	// 	gasPrice: 5000000000, // 5 Gwei
	// 	skipDryRun: false
	//   },
	  bscpublic: {
	    provider: new HDWalletProvider(process.env.ACCOUNT_KEY, "https://bsc-dataseed.binance.org/"),
	    network_id: 56,
	    gas: 3000000,
		gasPrice: 5000000000, // 5 Gwei
		skipDryRun: false
	  }
	},
	compilers: {
		solc: {
			version: "^0.6.6",
		},
	},
	plugins: ["truffle-plugin-verify"],
	api_keys: {
	  etherscan: process.env.BSCSCAN_API_KEY,
	},
}
