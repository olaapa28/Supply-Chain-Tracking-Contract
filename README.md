# 📦 Supply Chain Tracking Smart Contract

A transparent and secure blockchain-based solution for tracking products throughout their entire supply chain journey using Clarity smart contracts on Stacks.

## 🌟 Features

### 🏭 Product Management
- **Register Products**: Create new products with manufacturer details
- **Track Stages**: Monitor products through various supply chain stages
- **Transfer Ownership**: Seamlessly transfer product ownership between parties
- **Verify Authenticity**: Validate product authenticity with verification system

### 🔐 Access Control
- **Role-Based Authorization**: Manage who can interact with the contract
- **Owner Controls**: Special privileges for contract deployer
- **Actor Management**: Authorize/revoke access for supply chain participants

### 📊 Transparency Features
- **Complete History**: View full product journey from creation to current state
- **Event Logging**: Detailed tracking of all product movements and changes
- **Batch Operations**: Efficiently update multiple products simultaneously
- **Emergency Controls**: Stop problematic products immediately

## 🚀 Getting Started

### Prerequisites
- [Clarinet](https://github.com/hirosystems/clarinet) installed
- Basic understanding of Clarity smart contracts

### Installation

1. Clone this repository
```bash
git clone <repository-url>
cd supply-chain-tracking-contract
```

2. Install dependencies
```bash
npm install
```

3. Deploy the contract
```bash
clarinet deploy
```

## 📋 Usage Guide

### 🔧 Initial Setup

**Authorize Supply Chain Actors**
```clarity
(contract-call? .supply-chain-tracking-contract authorize-actor 'ST1MANUFACTURER "manufacturer")
(contract-call? .supply-chain-tracking-contract authorize-actor 'ST1DISTRIBUTOR "distributor")
(contract-call? .supply-chain-tracking-contract authorize-actor 'ST1RETAILER "retailer")
```

### 📦 Product Lifecycle

**1. Register a New Product**
```clarity
(contract-call? .supply-chain-tracking-contract register-product 
  "iPhone 15 Pro" 
  'ST1APPLE 
  "manufacturing" 
  "Cupertino, CA")
```

**2. Update Product Stage**
```clarity
(contract-call? .supply-chain-tracking-contract update-product-stage 
  u1 
  "quality-control" 
  "Factory Floor B" 
  "Passed initial quality checks")
```

**3. Transfer Ownership**
```clarity
(contract-call? .supply-chain-tracking-contract transfer-ownership 
  u1 
  'ST1DISTRIBUTOR 
  "Distribution Center" 
  "Transferred to primary distributor")
```

**4. Verify Product**
```clarity
(contract-call? .supply-chain-tracking-contract verify-product u1)
```

### 🔍 Query Functions

**Get Product Information**
```clarity
(contract-call? .supply-chain-tracking-contract get-product u1)
```

**Check Current Stage**
```clarity
(contract-call? .supply-chain-tracking-contract get-current-stage u1)
```

**View Product History**
```clarity
(contract-call? .supply-chain-tracking-contract get-product-history u1 u1)
```

**Check Verification Status**
```clarity
(contract-call? .supply-chain-tracking-contract is-product-verified u1)
```

### ⚡ Advanced Features

**Batch Update Multiple Products**
```clarity
(contract-call? .supply-chain-tracking-contract batch-update-stages 
  (list 
    { product-id: u1, stage: "shipped", location: "Warehouse A", notes: "Ready for delivery" }
    { product-id: u2, stage: "shipped", location: "Warehouse A", notes: "Ready for delivery" }
  ))
```

**Emergency Stop (Owner Only)**
```clarity
(contract-call? .supply-chain-tracking-contract emergency-stop u1)
```

## 🏗️ Contract Architecture

### 📊 Data Structures

**Products Map**
- `product-id`: Unique identifier
- `name`: Product name
- `manufacturer`: Creator principal
- `created-at`: Block height of creation
- `current-owner`: Current owner principal
- `current-stage`: Current supply chain stage
- `is-verified`: Verification status

**Product History Map**
- `product-id` + `event-id`: Composite key
- `stage`: Supply chain stage
- `location`: Physical location
- `timestamp`: Block height
- `actor`: Principal who made the change
- `notes`: Additional information

**Authorized Actors Map**
- `actor`: Principal address
- `role`: Actor role (manufacturer, distributor, etc.)
- `authorized`: Authorization status

### 🔄 Supply Chain Stages

Common stages include:
- `manufacturing` - Initial production
- `quality-control` - Quality assurance
- `packaging` - Product packaging
- `warehousing` - Storage facility
- `shipped` - In transit
- `delivered` - Final delivery
- `transferred` - Ownership change
- `EMERGENCY_STOP` - Flagged for issues

## 🛡️ Security Features

- **Access Control**: Only authorized actors can modify product data
- **Ownership Verification**: Transfers require proper authorization
- **Immutable History**: All events are permanently recorded
- **Emergency Controls**: Contract owner can immediately stop problematic products

## 🧪 Testing

Run the test suite:
```bash
clarinet test
```

## 🤝 Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🆘 Support

Need help? Open an issue or contact the development team.

---

*Built with ❤️ using Clarity smart contracts on Stacks blockchain*
