{
  inputs,
  cell,
}: let
  inherit (inputs.tullia) flakeOutputTasks taskSequence;
  inherit (inputs.nixpkgs) system lib;

  common = {config, ...}: {
    preset = {
      # needed on top-level task to set runtime options
      nix.enable = true;

      github-ci = {
        # Tullia tasks can run locally or on Cicero.
        # When no facts are present we know that we are running locally and vice versa.
        # When running locally, the current directory is already bind-mounted into the container,
        # so we don't need to fetch the source from GitHub and we don't want to report a GitHub status.
        enable = config.actionRun.facts != {};
        repo = "input-output-hk/cardano-base";
        sha = config.preset.github-ci.lib.getRevision inputs.cells.cloud.library.actionCiInputName null;
      };
    };
  };

  ciTasks =
    __mapAttrs
    (_: flakeOutputTask: {...}: {
      imports = [common flakeOutputTask];

      memory = 1024 * 8;
      nomad.resources.cpu = 10000;
    })
    (flakeOutputTasks ["hydraJobs" system] { outputs.hydraJobs.${system} = cell.hydraJobs; });

  ciTasksSeq = taskSequence "ci/" ciTasks (
    # make sure the aggregate is built last
    let
      required = "hydraJobs.${system}.required";
      all = __attrNames ciTasks;
    in
      assert __elem required all;
        lib.remove required all ++ [required]
  );
in
  ciTasks # for running separately
  // ciTasksSeq # for running in an arbitrary sequence
  // {
    "ci" = {lib, ...}: {
      imports = [common];
      after = __attrNames ciTasksSeq;
    };
  }
