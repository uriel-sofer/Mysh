#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <pwd.h>
#include <sys/types.h>
#include <signal.h>
#include <sys/errno.h>

#define MAX_JOBS 10 // Tracked background jobs
#define BUFFER_SIZE 1024
#define PROMPT_SUFFIX "mysh~~> "

typedef struct bgjob {
    pid_t pid;
    char command[BUFFER_SIZE];
} bgjob;

typedef struct {
    char ***segments;       // Array of segments (each a NULL-terminated argv)
    unsigned int count;     // Number of segments
} PipedSegments;

typedef struct stat stats;


static bool is_special_char(char c)
{
    return c == '&' || c == '<' || c == '>' || c == '|';
}

/**
 * @brief Tokenizes a given input line into separate words.
 *
 * This function splits the input line into tokens separated by spaces, tabs, or newlines.
 * The returned array is statically allocated and should not be freed by the caller.
 *
 * @param line The input string to tokenize. It will be modified by this function.
 * @param token_count Pointer to store the number of tokens parsed.
 * @return A NULL-terminated array of pointers to the tokens.
 */
char **tokenizer(char *line, unsigned int *token_count);

/**
 * @brief Handles built-in shell commands.
 *
 * This function checks if the first token corresponds to a recognized built-in command
 * like "bye", "bgjobs", "kill", or "mysh". If it matches, the command is executed internally.
 *
 * @param tokens Array of command tokens (first token is the command).
 * @param jobs Array for all the bg jobs
 * @param bgjobs_counter counter of current bg jobs running
 * @return true if a built-in command was handled, false otherwise.
 */
bool handle_builtin(char **tokens, bgjob *jobs, int *bgjobs_counter);

/**
 * @brief Executes a parsed command from tokens, handling background and foreground jobs.
 *
 * This function forks a new process to execute the given command tokens.
 * It checks if the command should run in the background (via '&') and updates
 * the background jobs list accordingly. If the command is a foreground job,
 * it waits for the child process to complete.
 *
 * @param tokens The array of command tokens (the first token is the command).
 * @param token_count The number of tokens parsed.
 * @param jobs The array to store background job information.
 * @param bgjobs_counter Pointer to the current count of background jobs.
 */
void execute_tokens(char **tokens, unsigned int token_count, bgjob *jobs, int *bgjobs_counter);

bool is_background_command(char **tokens, unsigned int *token_count);

/* BUILT-IN COMMANDS (helper functions) */
static bool handle_bye(const bgjob *jobs, const int *bgjobs_counter)
{
    for (int i = 0; i < *bgjobs_counter; i++)
        kill(jobs[i].pid, SIGKILL);

    exit(EXIT_SUCCESS);
}

static bool handle_bgjobs(bgjob *jobs, const int *bgjobs_counter)
{
    printf("pid\tbgjob\n");
    for (int i = 0; i < *bgjobs_counter; i++)
        printf("%d\t%s\n", jobs[i].pid, jobs[i].command);

    return true;
}

static bool handle_kill(char **tokens, bgjob *jobs, int *bgjobs_counter)
{
    if (tokens[1] == NULL)
    {
        printf("kill requires a PID\n");
        return true;
    }

    char *endptr;
    const long target_pid_long = strtol(tokens[1], &endptr, 10);
    if (*endptr != '\0' || target_pid_long <= 0)
    {
        printf("Invalid PID '%s'\n", tokens[1]);
        return true;
    }
    const int target_pid = (int) target_pid_long;

    bool found = false;

    for (int i = 0; i < *bgjobs_counter; i++)
    {
        if (jobs[i].pid == target_pid)
        {
            kill(target_pid, SIGKILL);
            printf("Killed job with PID %d\n", target_pid);

            // Drag the other jobs back
            for (int j = i; j < *bgjobs_counter - 1; j++)
                jobs[j] = jobs[j + 1];

            (*bgjobs_counter)--;

            found = true;
            break;
        }
    }

    if (!found)
        printf("No such background job with PID %d\n", target_pid);

    return true;
}

static bool handle_mysh(char **tokens, bgjob *jobs, int *bgjobs_counter)
{
    if (tokens[1] == NULL)
    {
        printf("mysh**: missing filename\n");
        return true;
    }

    FILE *f = fopen(tokens[1], "r");
    if (!f)
    {
        perror("fopen");
        return true;
    }

    char *line = NULL;
    size_t n = 0;
    while (getline(&line, &n, f) != -1)
    {
        // Ignore # Comments and empty lines
        if (line[0] != '#' && strlen(line) > 0)
        {
            unsigned int token_count;
            char **inner_tokens = tokenizer(line, &token_count);

            if (inner_tokens[0] != NULL)
            {
                if (handle_builtin(inner_tokens, jobs, bgjobs_counter))
                    continue;

                execute_tokens(inner_tokens, token_count, jobs, bgjobs_counter);
            }
        }
    }

    free(line);
    fclose(f);
    return true;
}

static bool is_exit_builtin(char** tokens)
{
    return tokens[0] && (strcmp(tokens[0], "exit") == 0 || strcmp(tokens[0], "bye") == 0);
}


char *generate_prompt(const char *username, const char *hostname)
{
    char *cwd = getcwd(NULL, 0);
    if (!cwd) return NULL;

    const char *base = cwd;
    const char *slash = strrchr(cwd, '/');
    if (slash) base = slash + 1;

    char *prompt = malloc(BUFFER_SIZE);
    if (!prompt)
    {
        free(cwd);
        return NULL;
    }

    snprintf(prompt, BUFFER_SIZE, "%s@%s %s %s", username, hostname, base, PROMPT_SUFFIX);
    free(cwd);
    return prompt;
}

void initialize_user_and_hostname(char username[BUFFER_SIZE], char hostname[BUFFER_SIZE])
{
    const struct passwd *pw = getpwuid(getuid());
    if (pw && pw->pw_name)
        strncpy(username, pw->pw_name, BUFFER_SIZE - 1);
    else
        strncpy(username, "user", BUFFER_SIZE - 1);
    username[BUFFER_SIZE - 1] = '\0';

    if (gethostname(hostname, BUFFER_SIZE) != 0)
        strncpy(hostname, "localhost", BUFFER_SIZE - 1);
    hostname[BUFFER_SIZE - 1] = '\0';
}

static char **prepare_tokens(const char *line, unsigned int *token_count)
{
    static char line_copy[BUFFER_SIZE];
    strncpy(line_copy, line, BUFFER_SIZE - 1);
    line_copy[BUFFER_SIZE - 1] = '\0';
    return tokenizer(line_copy, token_count);
}

int main(void)
{
    int bgjobs_counter = 0;
    bgjob jobs[MAX_JOBS];
    char *line = NULL;

    char username[BUFFER_SIZE];
    char hostname[BUFFER_SIZE];
    initialize_user_and_hostname(username, hostname);

    while (true)
    {
        fflush(stdout);
        fflush(stderr);

        char *prompt = generate_prompt(username, hostname);
        if (prompt)
        {
            printf("%s", prompt);
            free(prompt);
        }
        fflush(stdout);
        fflush(stderr);
        // Read line
        size_t n = 0;
        if (getline(&line, &n, stdin) == -1)
            break;

        unsigned int token_count;
        char **tokens = prepare_tokens(line, &token_count);

        if (is_exit_builtin(tokens))
        {
            handle_builtin(tokens, jobs, &bgjobs_counter);
            break;
        }

        execute_tokens(tokens, token_count, jobs, &bgjobs_counter);
        fflush(stdout);
        fflush(stderr);
        free(line);
        line = NULL;
    }
    free(line);
    return 0;
}

char **tokenizer(char *line, unsigned int *token_count)
{
    static char *tokens[BUFFER_SIZE];
    *token_count = 0;

    char *token = strtok(line, " \t\n");
    while (token != NULL)
    {
        const size_t len = strlen(token);
        // Handle token ending with &, <, >, or |
        if (len > 1 && is_special_char(token[len - 1]))
        {
            const char last_char = token[len - 1];
            token[len - 1] = '\0';
            tokens[*token_count] = token;
            (*token_count)++;
            tokens[*token_count] =
                (last_char == '&') ? "&" :
                (last_char == '<') ? "<" :
                (last_char == '>') ? ">" : "|";
            (*token_count)++;
        } else
        {
            tokens[*token_count] = token;
            (*token_count)++;
        }
        token = strtok(NULL, " \t\n");
    }

    tokens[*token_count] = NULL;
    return tokens;
}

bool handle_builtin(char **tokens, bgjob *jobs, int *bgjobs_counter)
{
    if (tokens[0] == NULL)
        return false;

    if (strcmp(tokens[0], "exit") == 0 || strcmp(tokens[0], "bye") == 0)
        return handle_bye(jobs, bgjobs_counter);

    if (strcmp(tokens[0], "bgjobs") == 0)
        return handle_bgjobs(jobs, bgjobs_counter);

    if (strcmp(tokens[0], "kill") == 0)
        return handle_kill(tokens, jobs, bgjobs_counter);

    if (strcmp(tokens[0], "mysh") == 0)
        return handle_mysh(tokens, jobs, bgjobs_counter);


    return false;
}

bool is_background_command(char **tokens, unsigned int *token_count)
{
    if (*token_count > 0 && tokens[*token_count - 1] && strcmp(tokens[*token_count - 1], "&") == 0)
    {
        tokens[*token_count - 1] = NULL;
        (*token_count)--;
        return true;
    }
    return false;
}

static PipedSegments pipes_segmentation(char **tokens, const unsigned int token_count, bgjob *jobs, int *bgjobs_counter)
{
    unsigned int pipe_count = 0;
    for (unsigned int i = 0; i < token_count; i++)
        if (tokens[i] && strcmp(tokens[i], "|") == 0)
            pipe_count++;

    if (pipe_count == 0)
    {
        char ***single_segment = malloc(2 * sizeof(char **));
        if (!single_segment)
        {
            perror("malloc");
            _exit(errno);
        }
        single_segment[0] = tokens;
        single_segment[1] = NULL;
        return (PipedSegments) { .segments = single_segment, .count = 1 };
    }

    const unsigned int segments_count = pipe_count + 1;
    char*** segments = calloc(segments_count, sizeof(char**)); // Still memory warning
    if (!segments)
    {
        perror("malloc");
        _exit(errno);
    }

    unsigned int seg_idx = 0;
    segments[seg_idx++] = tokens;

    for (unsigned int i = 0; i < token_count; i++)
    {
        if (tokens[i] && strcmp(tokens[i], "|") == 0)
        {
            tokens[i] = NULL;
            if (i + 1 < token_count)
                segments[seg_idx++] = &tokens[i + 1];
        }
    }

    return (PipedSegments) { .segments = segments, .count = segments_count };
}

// Used when tokenizing
void extract_input_output_redirection(char **tokens, const unsigned int token_count, const char **infile, const char **outfile)
{
    *infile = NULL;
    *outfile = NULL;
    for (unsigned int i = 0; i + 1 < token_count; i++)
    {
        if (tokens[i] && tokens[i + 1])
        {
            if (strcmp(tokens[i], "<") == 0)
            {
                *infile = tokens[i + 1];
                tokens[i] = NULL;
                tokens[i + 1] = NULL;
                i++; // Skip the next token since it's already processed
            }
            else if (strcmp(tokens[i], ">") == 0)
            {
                *outfile = tokens[i + 1];
                tokens[i] = NULL;
                tokens[i + 1] = NULL;
                i++; // Skip the next token since it's already processed
            }
        }
    }
}

// Used when executing children
void redirect_standard_streams(const char *infile, const char *outfile)
{
    if (infile)
    {
        if (freopen(infile, "r", stdin) == NULL)
        {
            perror("freopen infile");
            _exit(errno);
        }
    }
    if (outfile)
    {
        if (freopen(outfile, "w", stdout) == NULL)
        {
            perror("freopen outfile");
            _exit(errno);
        }
    }
}

// After background child fork
void handle_bg_job_execution(char **tokens, bgjob *jobs, int *bgjobs_counter, char **argv, const pid_t exec_line)
{
    if (*bgjobs_counter >= MAX_JOBS)
    {
        for (int i = 0; i < MAX_JOBS - 1; i++)
            jobs[i] = jobs[i + 1];
        (*bgjobs_counter)--;
    }

    jobs[*bgjobs_counter].pid = exec_line;
    const char *cmd = (argv[0] != NULL) ? argv[0] : "(null)";
    strncpy(jobs[*bgjobs_counter].command, cmd, BUFFER_SIZE - 1);
    jobs[*bgjobs_counter].command[BUFFER_SIZE - 1] = '\0';
    (*bgjobs_counter)++;

    printf("Started background job \"%s\" with PID %d\n", tokens[0], exec_line);
    fflush(stdout);
}

// After foreground child fork
void wait_for_process_completion(const char* cmd, const pid_t exec_line)
{
    int status;
    waitpid(exec_line, &status, 0);
    if (WIFEXITED(status))
    {
        const int exit_code = WEXITSTATUS(status);
        if (exit_code != 0)
            fprintf(stdout, "command not found: %s\nexited with status %d\n", cmd, exit_code);
    }
    fflush(stderr);
}

/**
 * Constructs a clean argv array for execvp command by nullifying irrelevant tokens like <, >, |, &
 * @param tokens tokens from the parsed line
 * @param token_count number of tokens
 * @return a clean argv array to send to exec command
 **/
static char** argv_construction(const char** tokens, const unsigned int token_count)
{
    unsigned int argc = 0;
    for (unsigned int i = 0; i < token_count; i++)
        if (tokens[i] != NULL)
            argc++;

    char **argv = malloc((argc + 1) * sizeof(char *));
    if (!argv) return NULL;

    unsigned int arg_index = 0;
    for (unsigned int i = 0; i < token_count; i++)
    {
        if (tokens[i] != NULL)
        {
            argv[arg_index] = malloc(strlen(tokens[i]) + 1);
            if (!argv[arg_index])
            {
                for (unsigned int j = 0; j < arg_index; j++)
                    free(argv[j]);
                free(argv);
                return NULL;
            }
            strcpy(argv[arg_index], tokens[i]);
            arg_index++;
        }
    }
    argv[arg_index] = NULL;
    return argv;
}

/**
 * Attaches pipes if needed: attaches the read end if '|' is before, and attaches the writing end if '|' is after.
 * @param segments segments between the pipes, each is a command
 * @param pipe_fds arrays to be piped()
 * @param i the index of the command in the segment chain
 */
void configure_process_io(const PipedSegments segments, int pipe_fds[], const unsigned int i)
{
    // If not the first command, attach stdin to the previous
    if (i > 0)
        dup2(pipe_fds[(i - 1) * 2], STDIN_FILENO);

    // If not the last command, attach stdout to the next
    if (i < segments.count - 1)
        dup2(pipe_fds[i * 2 + 1], STDOUT_FILENO);

    // Close the other fds
    for (unsigned int j = 0; j < 2 * (segments.count - 1); j++)
        close(pipe_fds[j]);
}

void execute_piped_commands(bgjob *jobs, int *bgjobs_counter, const PipedSegments segments)
{
    int pipe_fds[2 * segments.count - 1];
    for (unsigned int i = 0; i < segments.count - 1; i++)
    {
        // Open pipes
        if (pipe(pipe_fds + i * 2) == -1)
        {
            perror("pipe");
            _exit(errno);
        }
    }

    for (unsigned int i = 0; i < segments.count; i++)
    {
        const pid_t child_pid = fork();
        if (child_pid == -1)
        {
            perror("fork");
            _exit(errno);
        }

        if (child_pid == 0)
        {
            // Boy process
            unsigned int arg_count = 0;
            while (segments.segments[i][arg_count] != NULL)
                arg_count++;

            const char *infile = NULL;
            const char *outfile = NULL;
            extract_input_output_redirection(segments.segments[i], arg_count, &infile, &outfile);

            configure_process_io(segments, pipe_fds, i);

            redirect_standard_streams(infile, outfile);

            char** argv = argv_construction(segments.segments[i], arg_count);
            if (!argv)  _exit(EXIT_FAILURE);

            if (handle_builtin(segments.segments[i], jobs, bgjobs_counter))
            {
                // Free argv before exit
                for (char **p = argv; *p != NULL; ++p)
                    free(*p);
                free(argv);
                _exit(EXIT_SUCCESS);
            }

            execvp(argv[0], argv);
            // Debug print on exec failure
            fprintf(stderr, "Failed to exec: %s\n", argv[0]);
            perror("execvp");
            // Free argv before exit
            for (char **p = argv; *p != NULL; ++p)
                free(*p);
            free(argv);
            _exit(errno);
        }
    }

    for (unsigned int i = 0; i < 2*(segments.count - 1); i++)
        close(pipe_fds[i]);

    for (unsigned int i = 0; i < segments.count; i++)
        wait(NULL);
    // Free segments.segments before returning
    free(segments.segments);
}

void execute_tokens(char **tokens, unsigned int token_count, bgjob *jobs, int *bgjobs_counter)
{
    const PipedSegments segments = pipes_segmentation(tokens, token_count, jobs, bgjobs_counter);

    if (segments.count > 1)
    {
        execute_piped_commands(jobs, bgjobs_counter, segments);
        return;
    }

    if (tokens[0] == NULL)
        return;

    const char *infile;
    const char *outfile;

    extract_input_output_redirection(tokens, token_count, &infile, &outfile);

    const bool is_background = is_background_command(tokens, &token_count);

    char** argv = argv_construction(tokens, token_count);
    if (!argv)  return;

    const pid_t child_pid = fork();
    if (child_pid == -1)
    {
        perror("fork");
        // Free argv and its contents
        for (char **p = argv; *p != NULL; ++p)
            free(*p);
        free(argv);
        return;
    }

    // Boy process:
    if (child_pid == 0)
    {
        redirect_standard_streams(infile, outfile);

        if (handle_builtin(tokens, jobs, bgjobs_counter))
        {
            for (char **p = argv; *p != NULL; ++p)
                free(*p);
            free(argv);
            _exit(EXIT_SUCCESS);
        }

        execvp(argv[0], argv);
        perror("execvp");
        for (char **p = argv; *p != NULL; ++p)
            free(*p);
        free(argv);
        _exit(errno);
    }

    if (is_background)
        handle_bg_job_execution(tokens, jobs, bgjobs_counter, argv, child_pid);
    else
        wait_for_process_completion(argv[0], child_pid);

    // Free argv and its contents
    for (char **p = argv; *p != NULL; ++p)
        free(*p);
    free(argv);
}
