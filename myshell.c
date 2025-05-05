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

typedef struct stat stats;

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

/**
 * @brief Checks if the command should run in the background.
 *
 * If the last token is "&", removes it and signals background execution.
 *
 * @param tokens The array of tokens.
 * @param token_count Pointer to the count of tokens (might be updated).
 * @return true if background execution is requested, false otherwise.
 */
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
        printf("mysh**: kill requires a PID\n");
        return true;
    }

    char *endptr;
    const long target_pid_long = strtol(tokens[1], &endptr, 10);
    if (*endptr != '\0' || target_pid_long <= 0)
    {
        printf("mysh**: invalid PID '%s'\n", tokens[1]);
        return true;
    }
    const int target_pid = (int)target_pid_long;

    bool found = false;

    for (int i = 0; i < *bgjobs_counter; i++)
    {
        if (jobs[i].pid == target_pid)
        {
            kill(target_pid, SIGKILL);
            printf("mysh**: Killed job with PID %d\n", target_pid);

            // Drag the other jobs back
            for (int j = i; j < *bgjobs_counter - 1; j++)
                jobs[j] = jobs[j + 1];

            (*bgjobs_counter)--;

            found = true;
            break;
        }
    }

    if (!found)
        printf("mysh**: No such background job with PID %d\n", target_pid);

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

char* generate_prompt(const char* username, const char* hostname)
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

static char **prepare_tokens(const char *line, unsigned int *token_count) {
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
        char *prompt = generate_prompt(username, hostname);
        if (prompt)
        {
            printf("%s", prompt);
            free(prompt);
        }
        fflush(stdout);
        // Read line
        size_t n = 0;
        if (getline(&line, &n, stdin) == -1)
            break;

        unsigned int token_count;
        char **tokens = prepare_tokens(line, &token_count);

        if (handle_builtin(tokens, jobs, &bgjobs_counter))
        {
            free(line);
            line = NULL;
            continue;
        }

        execute_tokens(tokens, token_count, jobs, &bgjobs_counter);
        fflush(stdout);
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
    while (token != NULL) {
        // If a token ends with &, split it
        const size_t len = strlen(token);
        if (len > 1 && token[len - 1] == '&') {
            token[len - 1] = '\0';
            tokens[*token_count] = token;
            (*token_count)++;
            tokens[*token_count] = "&";
            (*token_count)++;
        } else {
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

    // This one is a bit unnecessary, it works the same as the shell's kill, but it was requested
    if (strcmp(tokens[0], "kill") == 0)
        return handle_kill(tokens, jobs, bgjobs_counter);

    if (strcmp(tokens[0], "mysh") == 0)
        return handle_mysh(tokens, jobs, bgjobs_counter);

    return false;
}

bool is_background_command(char **tokens, unsigned int *token_count)
{
    if (*token_count > 0 && strcmp(tokens[*token_count - 1], "&") == 0)
    {
        tokens[*token_count - 1] = NULL;
        (*token_count)--;
        return true;
    }
    return false;
}

void execute_tokens(char **tokens, unsigned int token_count, bgjob *jobs, int *bgjobs_counter)
{
    if (tokens[0] == NULL)
        return;

    const bool is_background = is_background_command(tokens, &token_count);

    const pid_t exec_line = fork();
    if (exec_line == -1)
    {
        perror("fork");
        return;
    }

    // Assign args dynamically
    char **argv = malloc((token_count + 1) * sizeof(char *));
    for (int i = 0; i < token_count; i++)
    {
        argv[i] = malloc(strlen(tokens[i]) + 1);
        strcpy(argv[i], tokens[i]);
    }

    // Boy process:
    if (exec_line == 0)
    {
        argv[token_count] = NULL;
        execvp(tokens[0], argv);
        perror("execvp");
        _exit(errno);
    }

    // Free them
    for (unsigned int i = 0; i < token_count; i++)
        free(argv[i]);
    free(argv);

    if (is_background)
    {
        if (*bgjobs_counter >= MAX_JOBS)
        {
            for (int i = 0; i < MAX_JOBS - 1; i++)
                jobs[i] = jobs[i + 1];
            (*bgjobs_counter)--;
        }

        jobs[*bgjobs_counter].pid = exec_line;
        strcpy(jobs[*bgjobs_counter].command, tokens[0]);
        (*bgjobs_counter)++;

        printf("Started background job \"%s\" with PID %d\n", tokens[0] ,exec_line);
        fflush(stdout);
    } else
    {
        int status;
        waitpid(exec_line, &status, 0);
        if (WIFEXITED(status))
        {
            const int exit_code = WEXITSTATUS(status);
            if (exit_code != 0)
                fprintf(stdout, "command exited with status %d\n", exit_code);
        }
        fflush(stdout);
    }
}
