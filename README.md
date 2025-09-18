# PagerDuty Level.io App Service

This service monitors alerts from Level.io and triggers/resolves incidents in PagerDuty. It is built using **Python** and hosted as an **Azure App Service**. It uses **Azure Cosmos DB** for state storage and **Application Insights** for logging and monitoring.

---

## Features

- Fetches alerts from Level.io API.
- Deduplicates alerts and triggers PagerDuty incidents.
- Resolves incidents automatically.
- Supports fallback and multiple PagerDuty routing keys.
- Logs and metrics sent to Application Insights.

---

## Prerequisites

- Azure subscription
- Azure App Service (Python 3.10+)
- Cosmos DB instance (SQL API)
- Application Insights resource
- PagerDuty account with service keys
- Level.io API access

---

## Azure App Service Setup

1. Create a **Python App Service** in Azure:
   - Select **Python 3.10+** as runtime.
   - Choose a region and plan according to your needs.

2. Ensure your **App Service** has **Networking** configured if Level.io requires IP whitelisting.

3. Add **Cosmos DB** and **Application Insights** resources in the same region for lower latency.

---

## Environment Variables

Set these in **App Service → Configuration → Application settings**:

```ini
# Azure Cosmos DB
COSMOS_ENDPOINT=<your_cosmos_endpoint>
COSMOS_KEY=<your_cosmos_primary_key>
COSMOS_DATABASE=<your_database_name>
COSMOS_CONTAINER=<your_container_name>

# Application Insights
APPINSIGHTS_INSTRUMENTATIONKEY=<your_instrumentation_key>

# PagerDuty
PAGERDUTY_ROUTING_KEY=<primary_routing_key>
PAGERDUTY_FALLBACK_KEY=<fallback_key>
PAGERDUTY_MULTI_KEYS={<optional_comma_separated_keys>}

# Level.io
LEVEL_API_KEY=<your_levelio_api_key>
LEVEL_API_URL=<optional_custom_api_url>

---

## Application insights

- Will only output to AppInsights if there is either error, or an alert. 

---

## Cosmos database

- Will hold the alerts, and clear them when they has been resolved. 