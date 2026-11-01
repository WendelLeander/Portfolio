# TryHackMe Blue Team CTF (Oct 2026): Tabletop Exercise - Dead on Arrival

*A write-up of the Dead on Arrival tabletop exercise from the 2026 Oct CTF (TryHackMe)*

📖 [Read the full write-up on Medium](https://medium.com/@wendelwalterleander/tryhackme-blue-team-ctf-oct-2026-tabletop-exercise-dead-on-arrival-2fc0399e864b)

---

## Challenge Description

<p align="center">
  <img src="images/img1.png" alt="image">
 </p>

**Dead on Arrival** is the tabletop exercise stage of the B2C2B 2026 Oct CTF: about an hour long, best done as a team, and built around handling a growing incident together, agreeing on priorities, communicating under pressure and keeping the business running, so you can see where your process falls short. There's no disk image, log file or flag to dig through here, since the whole thing is a series of decisions the team makes as the incident develops.

The scenario overview reads:

> *The final hours before a major product launch are tense enough without a company already known to adversaries watching its systems closely, and today that unease sits just beneath the surface of routine deployment work. As your team pushes toward a deadline the whole studio has been building towards, a handful of small, easily dismissed irregularities begin to surface in the background, the kind of thing that could mean nothing, or could mean someone else is already quietly present in your environment.*

| Exercise configuration | |
|---|---|
| Industry | Hardware & Electronics |
| Attacker objective | Sabotage |
| Environment | Windows |
| Architecture | Hybrid |
| Created by | TryHackMe |

**How the exercise works.** The welcome screen explains the format before it starts:

- **Real-time simulation:** everyone on the team sees the same injects and decides actions together, and the choices shape the narrative as it goes.
- **Collaborative evaluation:** every decision helps assess the team's response, and after voting you wait for the facilitator, since the results set the rhythm of the exercise.
- **Smart notes:** you can take notes at any time, and after each decision the platform suggests action-focused notes you can add.
- **Navigation and tools:** a timeline on the left lets you revisit past injects, and tools and references are available from the sidebar.

<p align="center">
  <img src="images/img2.png" alt="image">
 </p>

Each inject comes with a stage artefact (a Splunk notable event, for example), followed by decision questions such as how to triage the event, how to investigate further, and how to contain and eradicate the threat. After the team votes, the options are revealed ranked from most to least effective, together with a short host analysis of the team's choice.

**The scenarios.** The storyline is called *Pinstripe Moth Resurgence*, and it is told in three injects at a game studio called NeuralNexus, which ships its game at 17:00 UTC on launch day.

### Inject 1: Initial Access

<p align="center">
  <img src="images/img3.png" alt="image">
 </p>

It's launch day, and last night's threat hunt confirmed that the threat actor, Pinstripe Moth, is still inside. The workstation `THM-SREYES` is still beaconing to `45.147.230.131`, and the `svc-studioops` credentials that the deploy pipeline depends on are in the attacker's hands. Nothing has been remediated, and leadership has confirmed the launch goes ahead. At 09:42 UTC, Splunk shows `svc-studioops` logging into `BUILD-01` from `THM-SREYES` using NTLM, when the account normally authenticates only from the CI/CD orchestrator with Kerberos during scheduled builds. The session lasted under four minutes, no deployment job explains it, and Jada Collins confirms no manual build activity was scheduled. Sysmon on `BUILD-01` isn't reporting, and three Security log events from the session haven't been reviewed. The dilemma is that rotating `svc-studioops` now will break the release pipeline, while isolating `THM-SREYES` takes a developer offline on launch day, with seven hours and eighteen minutes left before launch.

The decisions here were about how to investigate further (for example triaging the three unreviewed Security events versus reviewing build artifact timestamps or chasing the missing Sysmon data) and how to contain and eradicate the threat (rotating the credentials in Jenkins and scoping the account to the CI server, isolating the workstation, blocking the C2 address, removing the persistence on the developer machine, or disabling the account outright).

### Inject 2: Lateral Movement & Privilege Escalation

<p align="center">
  <img src="images/img4.png" alt="image">
 </p>

The session on `BUILD-01` wasn't idle. At 10:07 UTC, `svc-studioops` opened a WinRM session from `BUILD-01` to `BAK-01`, the backup server nobody had checked yet, twenty minutes after the original logon ended, and Sysmon there is still blind. Within a minute a new local account, `backup-svc`, was created on `BAK-01` and added to Backup Operators, and PowerShell logging shows the attacker enumerating scheduled tasks and the permissions on `C:\Backups` before disconnecting. Nobody requested either change. Then, at 10:24 UTC, Michelle Smith calls the SOC: the official NeuralNexus social media account has just posted that the launch is delayed due to technical issues, with a link to an early access build hosted off-site, and it already has 400 reposts while Michelle can't log in to take it down. There are six hours and thirty-six minutes to launch, and as the narrative puts it, Pinstripe Moth is no longer being quiet.

This inject mixed technical and communication choices, such as escalating to the social platform's security team for takedown, briefing leadership, Legal and PR, warning the backup owners about the trustworthiness of the backups, reporting to the national cyber crime unit, or declaring a company-wide crisis with an external PR agency.

### Inject 3: Goal Execution

<p align="center">
  <img src="images/img5.png" alt="image">
 </p>

The `backup-svc` account turns out not to have been reconnaissance but setup. At 10:11 UTC, in the last seconds of its session on `BAK-01`, `svc-studioops` created a scheduled task called `BackupMaintenance` that runs as SYSTEM and has been running `purge-artifacts.ps1` every 15 minutes since 10:52. Last night's gold master is gone, along with the nightly archive on `FS-ARCHIVE` and every shadow copy, and Jada Collins confirms that only one verified restore point remains, with the next run at 11:37. Meanwhile the `BUILD-01` Security log finally reveals what was in the three unreviewed events: a scheduled task called `DeployPrep`, set to run once as `svc-studioops` at 16:55 to replace the signed release package with a modified build. Pinstripe Moth's plan is now clear, which is to destroy every clean restore point and then ship their own build under the studio's name, while the fake early access build is still circulating. It's 11:25 UTC, twelve minutes before the last backup is gone and five hours and thirty-five minutes before launch, and the team has to triage, investigate and contain it.

---

## Brief Summary

This is a decision-making exercise and not a technical one, so there's no vulnerability to exploit, and the core weakness is a compromised service account that the release pipeline depends on, which the team can't simply rotate or disable without hurting the launch. The team plays the defenders of a game studio on launch day, where an attacker group that was never evicted is still active, and the incident escalates over three injects: first a suspicious NTLM logon by a watchlisted account onto the build server, then lateral movement to the backup server with a new privileged account while the company's official social media account is hijacked to announce a fake delay, and finally the revelation that the attacker is purging every clean backup and has scheduled a swap of the signed release package for a modified build. At each step the team has to weigh surgical containment against keeping the business running, decide who needs to be told and when, and prioritise the action that stops the most active harm first, which is exactly what the exercise sets out to measure.

---

## Investigation Walkthrough

A tabletop exercise doesn't have a command line, so the investigation here was really the decisions themselves. Each question gave the team five possible actions and asked for the most effective one, and after voting the exercise ranked all five from most to least effective with a short host analysis. Below is each decision in order, the answer I went with, and why I think it was the best option. I picked the top-ranked answer in every decision I saw except one, which I point out when we get to it.

### Inject 1: Initial Access

**Investigate further.** *Pull and triage the three unreviewed Security log events from the 09:42 to 09:45 UTC session on BUILD-01.* Sysmon wasn't reporting on that host, so those three events were the only record of what the attacker actually ran, and reading them directly is better than guessing or waiting for better data. The exercise ranked pausing until Sysmon was restored as the least effective option, since that just burns time.

<p align="center">
  <img src="images/img6.png" alt="image">
 </p>

**Contain and eradicate.** *Work with Jada Collins to rotate the svc-studioops password in Jenkins and restrict the account to CI-01.* This cuts off the stolen credential the attacker was actively using without stopping the pipeline, so the launch isn't hurt. Isolating THM-SREYES, blocking the C2 address or killing the persistence script each only covers part of the problem, and disabling the account outright would have halted the release.

<p align="center">
  <img src="images/img7.png" alt="image">
 </p>

**Recovery.** *Audit every scheduled task and deploy script on BUILD-01 and CI-01 that runs as svc-studioops, removing anything Jada doesn't recognise before updating the rest with the new password.* A new password only helps if nothing the attacker planted still runs under that account, and cleaning first means we don't hand the new password to a malicious task. Logging the rotation as complete without testing was ranked the weakest option.

<p align="center">
  <img src="images/img8.png" alt="image">
 </p>

**Escalation.** *Brief Dana Brooks and launch leadership that the attacker has reached the build host, so they understand the risk to release integrity before the 17:00 UTC launch.* Leadership owns the launch decision, and an attacker on the build host is a direct risk to what ships, so they need to hear it early and not find out later.

<p align="center">
  <img src="images/img9.png" alt="image">
 </p>

### Inject 2: Lateral Movement & Privilege Escalation

**Triage.** *P0: the attacker has reached the backups and hijacked the official launch account, so declare a Critical incident and bring in leadership, Dana, Jada, Luke, Comms and Legal.* The backup server and the fake social post both point to the same actor running a coordinated sabotage campaign, so treating them as one big incident keeps the response joined up. Splitting the hijacked account off to Marketing or logging it quietly would have fragmented it.

<p align="center">
  <img src="images/img10.png" alt="image">
 </p>

**Investigate further.** *Pull BUILD-01's own Windows event logs (4688, 4698, 5156) to find what's still running as svc-studioops.* Sysmon was still blind there, so the native Windows logs for process creation, scheduled tasks and network connections were the only way to see what was still acting as that account. Reviewing the social account's login history was ranked least effective since it doesn't tell us anything about the pipeline.

<p align="center">
  <img src="images/img11.png" alt="image">
 </p>

**Contain and eradicate.** *Work with the social platform to recover the NeuralNexus account, remove the fake post and revoke all active sessions.* The fake post was live, had 400 reposts and was pointing people to an off-site build, so it was the most active damage and something we could stop right away. Isolating BAK-01 and disabling backup-svc was the runner-up.

<p align="center">
  <img src="images/img12.png" alt="image">
 </p>

**Recovery.** *Validate BAK-01's backup data against known-good checksums before relying on it for any restore or rebuild.* The attacker had been on the backup server, so I can't trust the backups until they're proven clean, and restoring from tampered data could be worse than having no restore at all.

<p align="center">
  <img src="images/img13.png" alt="image">
 </p>

**Escalation.** *Update leadership, Legal and PR on the public impersonation and the attacker's move onto the backups, so they can manage launch messaging and the go/no-go decision.* This is the one decision where I wasn't top-ranked, since the exercise rated it Effective (second). I picked it because the decision-makers need the full picture, but the most effective action was escalating straight to the social platform's security team for emergency recovery and takedown, because the fraudulent post was still live and causing reputational damage with every passing minute. That's the one answer I'd swap if I did it again.

<p align="center">
  <img src="images/img14.png" alt="image">
 </p>

### Inject 3: Goal Execution

**Triage.** *P0: backups are being destroyed and a malicious build is staged to ship, so declare a Critical incident and bring leadership, Legal, Jada, Luke and Comms into the launch decision immediately.* This threatens both the last recovery option and the integrity of the release, so it needed the biggest scale of response with every decision-maker in at once. Declaring only a High incident and holding off on leadership would have wasted the narrow window to stop a sabotaged release.

<p align="center">
  <img src="images/img15.png" alt="image">
 </p>

**Investigate further.** *Sweep Splunk for every svc-studioops logon, WinRM session and scheduled task creation across all hosts to find any persistence beyond BAK-01 and BUILD-01.* The attacker had already hidden two scheduled tasks that we only found late, so I wanted to know if there were more before locking in containment. Looking at DeployPrep's payload only answers one question and not the bigger one.

<p align="center">
  <img src="images/img16.png" alt="image">
 </p>

**Contain and eradicate.** *Disable the BackupMaintenance task on BAK-01 and kill purge-artifacts.ps1 before the 11:37 run, preserving the last restore point.* It was a race against the clock, since the next purge would delete the only remaining clean restore point and that was the one containment step that couldn't wait. Disabling DeployPrep was the runner-up, but that task doesn't fire until 16:55, which gives us hours.

<p align="center">
  <img src="images/img17.png" alt="image">
 </p>

**Recovery.** *Copy the last restore point to segregated offline storage and verify its checksum, keeping it out of BAK-01 until the server is rebuilt.* It protects our only safety net from the same attacker even if containment slips, by getting it out of reach. Triggering a fresh gold master backup from the compromised build host would have been much weaker.

<p align="center">
  <img src="images/img18.png" alt="image">
 </p>

**Escalation.** *Brief the launch steering committee on the staged release swap, the backup loss and the current containment status so they can make the 17:00 go/no-go call.* That decision belongs to the committee and they need one clear, consolidated picture to make it. Sending an emergency alert to everyone first was ranked the weakest choice, since it could spread unverified information right before launch.

<p align="center">
  <img src="images/img19.png" alt="image">
 </p>

### What stuck with me

Looking back at all of it, the pattern I kind of settled into was to stop the most urgent, time-critical harm first, keep the business running where I could, and get the people who own the big decisions the full picture quickly. The one answer that missed the top rank was a case of choosing who to tell before choosing what to stop, and the exercise was pretty clear that the active harm comes first.

<p align="center">
  <img src="images/img20.png" alt="image">
 </p>
