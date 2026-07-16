# UMSH User Interface Guidelines

UMSH runs on devices ranging from keyboard-equipped pagers to sealed trackers
with one button and no screen. This guide defines a common user-interface
philosophy for that range. Its goal is not to make unlike hardware behave
identically. Its goal is to make UMSH devices feel related: the same concepts,
the same safety rules, and feedback that means the same thing even when it is
expressed through a screen, LED, buzzer, haptic motor, or companion phone.

The primary division is functional, not merely physical: a **pager** is a
self-contained UMSH device, while a **tracker** may perform tracking
autonomously but is typically operated and configured through a phone. A
keyboard is a strong pager signal because it makes direct messaging practical;
a screen by itself does not make a device a pager.

The intended reader is a developer bringing UMSH to a new board. Begin with
[Device Classes](device-classes.md), inventory the board using [Capability
Profiles](capability-profiles.md), and then map the common interaction model to
the available controls and indicators.

## Scope and maturity

This is an early design outline. It contains three kinds of guidance:

- **Principle** describes the intended cross-device experience.
- **Current behavior** records behavior already present in the repository.
- **Proposed mapping** applies the principles to hardware whose UMSH user
  interface is not implemented yet.

Examples must retain these labels until their behavior is verified on hardware.
Normative words such as **must**, **should**, and **may** describe the target
experience, not necessarily the state of every current firmware image.

This guide covers product interaction. Electrical details, pin assignments, and
firmware architecture belong in the board hardware references and
`docs/firmware-architecture.md`.
