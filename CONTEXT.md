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

**Synthetic Tenant**:
A disposable fictitious isolation boundary used before Enterprise Onboarding. It can never be upgraded in place into a Tenant for a Target Enterprise.
_Avoid_: Demo customer, future real Tenant

**Enterprise User**:
A person admitted to a Tenant under that Target Enterprise's runtime authorization.
_Avoid_: Product Owner, project proposer

**Tenant Principal**:
A human, Agent, or service identity admitted to one Tenant and governed by that Tenant's runtime authorization.
_Avoid_: Product Owner, email, global user

**Enterprise Authorized Onboarding Principal**:
The Target Enterprise representative formally authorized to submit or confirm onboarding inputs. This authority cannot be delegated by the Product Owner.
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
The authorized, frozen, and traceable P3 configuration and evidence input for one Tenant. It references but never embeds production secrets.
_Avoid_: P0 materials, early discovery pack

**Data Policy Pack**:
The Target Enterprise's versioned rules for data classification, model and region use, retention, deletion, audit, backup, and quotas within one Tenant.
_Avoid_: Product policy, privacy summary

**Tenant Isolation Profile**:
The per-Tenant choice of shared or dedicated data and runtime boundaries. It changes isolation topology without forking Product Core.
_Avoid_: Connector Stage, pricing tier

**Product Phase**:
One of the four ordered scopes P0 through P3. A Product Phase contains work packages and ends at a Stage Gate.
_Avoid_: Connector Stage, work package

**Stage Approval**:
The Product Owner's Gate Decision over one exact Frozen Evidence Package submitted at a Stage Gate.
_Avoid_: Department approval, runtime authorization

**Stage Gate**:
The exit boundary of a Product Phase. G0 through G2 may open the next phase, while G3 accepts or rejects one Tenant's onboarding.
_Avoid_: Project task, informal review

**Project Work Package**:
One independently scoped and accepted unit of product or onboarding work. It is not necessarily a service, repository, deployment, team, or person.
_Avoid_: Microservice, component instance, department

**Frozen Evidence Package**:
The immutable, versioned set of deliverables and test evidence presented for Stage Approval, identified by a content hash.
_Avoid_: Progress summary, mutable folder

**Gate Submission**:
One immutable attempt to pass a Stage Gate, containing a Frozen Evidence Package and its content hash.
_Avoid_: Mutable approval request, stage

**Gate Decision**:
One immutable Product Owner decision on one Gate Submission: approve, approve with permitted exclusions, return, or hold.
_Avoid_: Runtime authorization, editable status

**Work Package Applicability**:
The per-Tenant P3 classification of a conditional onboarding work package as required, optional, or not in scope.
_Avoid_: Completion status, exclusion after failure

**Runtime Authorization**:
The Target Enterprise authority governing Tenant Principals, data, resources, Connector capabilities, and actions inside one Tenant.
_Avoid_: Stage Approval

**HumanDecision**:
A Tenant runtime decision made by an authorized Enterprise User, represented by a Human Tenant Principal, over an exact frozen business artifact. It does not grant or replace Stage Approval.
_Avoid_: Stage Approval, chat confirmation

**Synthetic Test Decision**:
A P1 test record made by a synthetic Human Principal to verify the HumanDecision mechanism without authorizing a real external effect.
_Avoid_: HumanDecision, production approval

**Stable Principal**:
The Tenant-scoped identity that remains stable when a person's email, display name, or external identity provider changes.
_Avoid_: Email, username, employee number

**Connector Template**:
A reusable product integration contract built without any Target Enterprise credentials or network access.
_Avoid_: Live Connector

**Connector Instance**:
A P3 Tenant-specific activation of a Connector Template, advanced through controlled connection stages.
_Avoid_: Connector Template

**Connector Stage**:
The independently evidenced state of one Connector Instance: disabled, authorized snapshot, controlled read, or controlled write.
_Avoid_: Product stage, shared enterprise capability
