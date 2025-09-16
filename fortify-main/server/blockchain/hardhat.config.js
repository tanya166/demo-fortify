require("@nomicfoundation/hardhat-toolbox");

require("dotenv").config({ path: '../../.env' });

module.exports = {
  networks: {
    sepolia: {
      url: process.env.INFURA_RPC_URL,
      accounts: [process.env.PRIVATE_KEY],
    },
  },
  etherscan: {
    apiKey: process.env.ETHERSCAN_API_KEY,
  },
  solidity: "0.8.28", 
  sourcify: {
    enabled: true
  },
};
