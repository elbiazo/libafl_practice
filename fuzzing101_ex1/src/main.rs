use libafl::bolts::rands::StdRand;
use libafl::bolts::shmem::{ShMem, ShMemProvider, StdShMemProvider};
use libafl::bolts::tuples::{tuple_list, Merge};
use libafl::bolts::{current_nanos, AsMutSlice};
use libafl::corpus::{
    Corpus, InMemoryCorpus, IndexesLenTimeMinimizerCorpusScheduler, OnDiskCorpus,
    QueueCorpusScheduler,
};
use libafl::events::SimpleEventManager;
use libafl::executors::{ForkserverExecutor, TimeoutForkserverExecutor};
use libafl::feedbacks::{AflMapFeedback, CrashFeedback, MapFeedbackState, MaxMapFeedback, TimeFeedback, TimeoutFeedback};
use libafl::inputs::BytesInput;
use libafl::monitors::SimpleMonitor;
use libafl::mutators::{havoc_mutations, tokens_mutations, StdScheduledMutator, Tokens};
use libafl::observers::{ConstMapObserver, HitcountsMapObserver, TimeObserver};
use libafl::stages::StdMutationalStage;
use libafl::state::{HasCorpus, HasMetadata, StdState};
use libafl::{feedback_and_fast, feedback_or, Fuzzer, StdFuzzer};
use std::path::PathBuf;
use std::time::Duration;

fn main() {
    let crashes = PathBuf::from("./crashes");

    // Corpus directory
    let corpus_dirs = vec![PathBuf::from("./corpus")];

    // Creating Shared memory with AFL_SHM_ID
    const MAP_SIZE: usize = 65336;
    let mut shmem_provider = StdShMemProvider::new().expect("Couldn't get std shmem provider");
    let mut shmem = shmem_provider.new_shmem(MAP_SIZE).unwrap();
    shmem
        .write_to_env("__AFL_SHM_ID")
        .expect("Failed to write afl shm id to env");

    let shmem_buf = shmem.as_mut_slice();

    //
    // An Observer, or Observation Channel, is an entity that provides an information observed during the execution of the program under test to the fuzzer.
    // The information contained in the Observer is not preserved across executions.
    //

    // ConstMapObserver is used when you already know the map size.
    // HitcountsMapObserver is used to see if input is interesting with hitcounts postprocessing.
    let edges_observer = HitcountsMapObserver::new(ConstMapObserver::<_, MAP_SIZE>::new(
        "shared_mem",
        shmem_buf,
    ));

    // Create observer to keep track of the execution time
    let time_observer = TimeObserver::new("time");

    //
    // Feedbacks
    //

    // Contains information about current untouched entries
    let feedback_state = MapFeedbackState::with_observer(&edges_observer);

    // Contains information about overall untouched entries
    let crash_edges_state = MapFeedbackState::new("crash_edges", MAP_SIZE);
    //
    // Feedback
    //

    // creates feedback for time and tracking hit count post processing
    let feedback = feedback_or!(
        // Todo: Wtf is novelties. and what is it to track indexes
        MaxMapFeedback::new_tracking(&feedback_state, &edges_observer, true, false),
        // Get Time feedback
        TimeFeedback::new_with_observer(&time_observer)
    );

    let objective = feedback_and_fast!(
        // Must be a crash
        TimeoutFeedback::new(),
        // Take it only if trigger new coverage over crashes
        MaxMapFeedback::new(&crash_edges_state, &edges_observer)
    );

    //
    // State
    //

    let mut state = StdState::new(
        StdRand::with_seed(current_nanos()),
        InMemoryCorpus::<BytesInput>::new(),
        OnDiskCorpus::new(crashes).expect("Failed to create on disk corpus"),
        tuple_list!(feedback_state, crash_edges_state),
    );

    // Create monitor to report fuzzer stat
    let monitor = SimpleMonitor::new(|s| println!("{}", s));

    let mut mgr = SimpleEventManager::new(monitor);

    let scheduler = IndexesLenTimeMinimizerCorpusScheduler::new(QueueCorpusScheduler::new());

    let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);



    // Todo: wtf is tokens
    let mut tokens = Tokens::new();
    let forkserver = ForkserverExecutor::builder()
        .program("./xpdf/bin/pdftotext".to_string())
        .debug_child(false)
        .shmem_provider(&mut shmem_provider)
        .autotokens(&mut tokens)
        .parse_afl_cmdline(&[String::from("@@")])
        .build(tuple_list!(edges_observer,time_observer))
        .unwrap();

    let mut executor = TimeoutForkserverExecutor::new(
        forkserver,
        Duration::from_millis(
            // 1 second
            1000,
        ),
    )
    .expect("Failed to create the executor");

    // In case the corpus is empty (on first run), reset
    if state.corpus().count() < 1 {
        state
            .load_initial_inputs(&mut fuzzer, &mut executor, &mut mgr, &corpus_dirs)
            .expect("Failed to load initial inputs");
        println!("We imported {} inputs from disk.", state.corpus().count());
    }

    state.add_metadata(tokens);

    // Setup a mutational stage with a basic bytes mutator
    let mutator = StdScheduledMutator::new(havoc_mutations().merge(tokens_mutations()));
    let mut stages = tuple_list!(StdMutationalStage::new(mutator));

    fuzzer
        .fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr)
        .expect("Error in the fuzzing loop");
}
