# Multi-enterprise AI Platform

This context separates the reusable product from any enterprise that later adopts it. It also separates product-stage approval from an enterprise tenant's runtime authorization.

## Language

**Product Owner**:
The external owner of the reusable product and the sole approver of each project stage. The Product Owner is not an employee or user of a Target Enterprise merely by holding this role.
_Avoid_: Internal project lead, enterprise employee, department Owner

**Target Enterprise**:
An organization that adopts the product during Enterprise Onboarding.
_Avoid_: The company, our company

**Tenant**:
The isolated product boundary created for one Target Enterprise.
_Avoid_: Workspace, department

**Enterprise User**:
A person admitted to a Tenant under that Target Enterprise's runtime authorization.
_Avoid_: Product Owner, project proposer

**Product Core**:
The enterprise-neutral capabilities built and verified before any Target Enterprise is onboarded.
_Avoid_: Company system, internal platform

**Synthetic Fixture**:
Fictitious users, documents, organizations, workflows, and system responses used to build and verify the Product Core.
_Avoid_: Sample company data, anonymized live data

**Public Enterprise Context**:
Information already published to the public about a possible Target Enterprise. It can provide background before onboarding but is not authoritative internal data.
_Avoid_: Enterprise truth, approved internal knowledge

**Enterprise Onboarding Package**:
The P3 input that configures one Tenant with authorized enterprise identity, users, knowledge, policies, system interfaces, and acceptance criteria.
_Avoid_: P0 materials, early discovery pack

**Stage Approval**:
The Product Owner's single recorded decision to accept a completed project stage and permit the next stage to start.
_Avoid_: Department approval, runtime authorization

**Runtime Authorization**:
The permissions configured inside a Tenant for Enterprise Users, knowledge, tools, and actions.
_Avoid_: Stage Approval

**Connector Template**:
A reusable product integration contract built without any Target Enterprise credentials or network access.
_Avoid_: Live Connector

**Connector Instance**:
A P3 Tenant-specific activation of a Connector Template, advanced through controlled connection stages.
_Avoid_: Connector Template
