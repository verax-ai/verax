/**
 * System32 module directory loads for PowerShell started with systemToolEnv().
 *
 * #119, measured on windows-full 5a75875: under that environment PSModulePath is
 * only the System32 Windows PowerShell 5.1 module directory, and resolving an
 * autoloaded cmdlet (ConvertFrom-Json) took 23 to 30 s on a GitHub Windows
 * runner. Import-Module of the same module by its System32 path took 0.27 s.
 * Each statement names the module directory. LocalAccounts lives in a version
 * subdirectory (1.0.0.0 on the measured Windows 11 machine); importing the
 * directory lets Windows PowerShell choose that version and stay inside System32.
 */
export const PS_MODULES = [
  "Microsoft.PowerShell.Utility",
  "Microsoft.PowerShell.Management",
  "Microsoft.PowerShell.Security",
  "Microsoft.PowerShell.LocalAccounts",
  "ScheduledTasks",
] as const;

export type PsModule = (typeof PS_MODULES)[number];

/** One Import-Module statement. The expected line shape lives only here. */
export function psModuleImportLine(module: PsModule): string {
  return `Import-Module "$env:SystemRoot\\System32\\WindowsPowerShell\\v1.0\\Modules\\${module}"`;
}

/** One line per module, in the given order. A repeated module is emitted once. */
export function psModuleImports(modules: readonly PsModule[]): string {
  const seen = new Set<PsModule>();
  const lines: string[] = [];
  for (const module of modules) {
    if (seen.has(module)) continue;
    seen.add(module);
    lines.push(psModuleImportLine(module));
  }
  return lines.join("\n");
}
