#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <regex.h>
#include <errno.h>
#include <sys/time.h>

#define T_A 1 /* Тип записи IPv4 адреса	*/
#define T_CNAME 5 /* Тип записи канонического имени (canonical name) */

/* Структура заголовка DNS пакета 
(битовые поля необходимы для корректной интерпретации пакета)*/
typedef struct {
	uint16_t id; /* Идентификатор запроса */

	uint8_t rd :1; /* Рекурсивный запрос (recursion desired) */
	uint8_t tc :1; /* Усеченное сообщение (truncation) */
	uint8_t aa :1; /* Авторитетный ответ (authoritive answer) */
	uint8_t opcode :4; /* Тип запроса:
	0 - cтандартный запрос;
	1 - инверсный запрос;
	2 - запрос статуса сервера. */
	uint8_t qr :1; /* Запрос - 0, Ответ - 1 (query/response) */

	uint8_t rcode :4; /* Код ответа (response code) */
	uint8_t cd :1; /* Отключить проверку подписи (DNSSEC) (checking disabled) */
	uint8_t ad :1; /* Аутентифицированные данные (только DNSSEC) (authenticated data) */
	uint8_t z :1; /* Зарезервирован */
	uint8_t ra :1; /* Рекурсия возможна (recursion available) */

	uint16_t qdcount; /* Количество записей в секции запросов */
	uint16_t ancount; /* Количетво записей в секции ответов */
	uint16_t nscount; /* Количетво записей в авторитетной секции */
	uint16_t arcount; /* Количетво записей в дополнительной секции */
} dns_header_t;

/* Структура секции запроса DNS пакета*/
typedef struct {
	uint8_t *name; /* Доменное имя в виде серии меток. Первые два бита определяют тип меток:
	00 - стандартная метка (3www6google3com);
	11 - сжатая метка (следующие 14 бит определяют начальный адрес серии меток. */
	uint16_t qtype; /* Тип искомой DNS записи (A, CNAME etc.) */
	uint16_t qclass; /* Класс запроса (IN для Internet) */
} dns_question_t;

/* Поля ресурсных записей DNS пакета константной длины
(необходимо упаковать во избежание выравнивания полей для корректной интерпретации) */
struct __attribute__((packed)) dns_const_fields {
	uint16_t type; /* Тип ресурсной записи */
	uint16_t class; /* Класс ресурсной записи */
	uint32_t ttl; /* Время жизни ресурсной записи (в кэше) */
	uint16_t rdlength; /* Длина поля данных (rdata)*/
};

/* Указатели на содержимое ресурсных записей */
typedef struct {
	uint8_t *name; /* Доменное имя */
	struct dns_const_fields *resource;
	uint8_t *rdata; /* Поле данных*/
} dns_record_t;


/* Функция для преобразования доменного имени в формат DNS:
www.yandex.ru -> 3www6yandex2ru */
void domain_to_dns_format(uint8_t*, uint8_t*); 

/* Функция для преобразования строкового адреса в шестнадцатеричный вид:
(127.0.0.53) -> (0x7F000035) */
uint32_t addr_to_hex(char*);

/* Функция для проверки корректности доменного имени */
int check_domain(char*);

/* Функция для распаковки сжатого доменного имени в секции ответов DNS пакета */
uint8_t* decompress(uint8_t*, uint8_t*, int*);

int main(int argc, char **argv) {
	uint8_t buf[4096];
	uint32_t dns_server;
    int socketfd;

    if (argc < 2 || argc > 3) {
        fprintf(stderr, "Usage: %s <domain> [DNS server]\n", *argv);
        return -1;
    } else if (check_domain(argv[1]) != 0) {
		fprintf(stderr, "Domain name is not valid\n", argv[1]);
		return -3;
	} else if (argc == 2) {
		dns_server = addr_to_hex("8.8.8.8"); // Google public DNS server 
	} else if ((dns_server = addr_to_hex(argv[2])) == 0) {
		fprintf(stderr, "Invalid dns server address format\n");
        return -1;
	}

    if ((socketfd = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
        fprintf(stderr, "Unexpected error during socket creation\n");
        return -2;        
    }

	/* Формирование адреса DNS сервера */
	struct sockaddr_in address;
    address.sin_family = AF_INET; 
    address.sin_addr.s_addr = dns_server; 
    address.sin_port = htons(53);

	/* Формирование заголовка */
	dns_header_t *dns;
	dns = (dns_header_t*) buf;

	dns->id = htons(getpid()); 
	dns->qr = 0; /* Тип - запрос */
	dns->opcode = 0; /* Стандартный запрос */
	dns->aa = 0; 
	dns->tc = 0; 
	dns->rd = 1; /* Рекурсия желательна */
	dns->ra = 0; 
	dns->z = 0;
	dns->ad = 0;
	dns->cd = 0;
	dns->rcode = 0;
	dns->qdcount = htons(1); /* Один запрос */
	dns->ancount = 0;
	dns->nscount = 0;
	dns->arcount = 0;

	/* Формирование запроса */
	dns_question_t question;
	question.qtype = htons( T_A ); /* Тип запроса - A (IPv4) */
	question.qclass = htons(1); /* Класс IN */

	question.name = (uint8_t*) calloc(strlen(argv[1]) + 2, sizeof(uint8_t));

	domain_to_dns_format(question.name, argv[1]); 

	ssize_t sent_size = sizeof(dns_header_t);

	/* Копирование DNS пакета в буфер */
	memcpy (buf + sent_size, question.name, strlen(question.name) + 1);
	sent_size += strlen(question.name) + 1;
    memcpy (buf + sent_size, &question.qtype, sizeof(question.qtype));
	sent_size += sizeof(question.qtype);
    memcpy (buf + sent_size, &question.qclass, sizeof(question.qclass));
	sent_size += sizeof(question.qclass);

	/* Отправка DNS пакета */
	if (sendto(socketfd,(char*)buf, sent_size, 0, (struct sockaddr*) &address, sizeof(address)) < 0) {
		fprintf(stderr, "Sendto failed \n");
		return -6;
	}

	/* Вывод отправленного пакета */
	printf("Raw data packet (total %ld bytes sent):\n", sent_size);

	for (int i=0; i < sent_size; i++) {
		printf("%02X ", buf[i]);
		if ((i+1)%16 == 0) printf("\n");
	}
	printf("\n\n");

	socklen_t length = 0;
	ssize_t recieve_size = 0;
	memset(buf, 0, 512);

	/* Установка таймера ожидания */
	struct timeval timeout;
	timeout.tv_sec = 5;
	timeout.tv_usec = 0;

	if (setsockopt(socketfd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout)) < 0) {
		fprintf(stderr, "Error setting socket timeout\n");
		return -9;
	}

	/* Получение DNS пакета от сервера */
	if ((recieve_size = recvfrom(socketfd, buf, 1024, 0, (struct sockaddr *) &address, &length)) < 0 ) {
		if(errno == EWOULDBLOCK || errno == EAGAIN) {
			fprintf(stderr, "Connection timed out; no servers could be reached \n");
		} else {
			fprintf(stderr, "Recvfrom failed \n");
		}
		return -7;
	}

	/* Вывод полученного пакета */
	printf("Raw data packet (total %ld bytes recieved):\n", recieve_size);

	for (int i=0; i < recieve_size; i++) {
		printf("%02X ", buf[i]);
		if ((i+1)%16 == 0) printf("\n");
	}

	printf("\n\n");

	/* Интерпретация заголовка */
	dns_header_t *response_header = (dns_header_t *) buf;
	
	if (response_header->rcode == 3) {
		fprintf(stderr, "** server can't find %s: NXDOMAIN\n", argv[1]);
		return -3;
	} else if (response_header->rcode != 0) {
		fprintf(stderr, "** an unexpected error has occurred (rcode = %d)\n", response_header->rcode);
		return -4;
	}

	if (ntohs(response_header->ancount) == 0) {
		fprintf(stderr, "*** can't find %s: No answer\n", argv[1]);
		return -5;
	}

	uint8_t *reader = buf + sent_size; /* Начать чтение пакета с секции ответов */
	struct sockaddr_in a;
	uint8_t *ans_name;
	int stop = 0;

	/* Интерпретация ресурсных записей */
	dns_record_t *answers = (dns_record_t*) calloc(response_header->ancount, sizeof(dns_record_t));

    for (int i = 0; i < ntohs(response_header->ancount); i++) { 
		ans_name = decompress(reader,buf,&stop); /* Распаковка сжатых доменных имен */
		printf("Name:	%s", ans_name);
		reader = reader + stop;

		answers[i].resource = (struct dns_const_fields*) (reader);

		reader = reader + sizeof(struct dns_const_fields);
		
		if(ntohs(answers[i].resource->type) == T_A) /* тип = address */
		{
			answers[i].rdata = (uint8_t*)malloc(ntohs(answers[i].resource->rdlength));

			for(int j = 0 ; j < ntohs(answers[i].resource->rdlength) ; j++) {
				answers[i].rdata[j] = reader[j];
			}

			answers[i].rdata[ntohs(answers[i].resource->rdlength)] = '\0';
			reader = reader + ntohs(answers[i].resource->rdlength);

			a.sin_addr.s_addr=*((long*)answers[i].rdata);
			printf("\nAddress: %s\n",inet_ntoa(a.sin_addr));
		} else { 
			answers[i].rdata = decompress(reader,buf,&stop);
			reader = reader + stop;

			if (ntohs(answers[i].resource->type) == T_CNAME) /* тип = canonical name */
				printf("	canonical name = %s\n", answers[i].rdata);	
		}

		free(ans_name); /* Освобождение памяти, выделенной для доменного имени */
	}

	/* Освобождение выделенной памяти */
	for (int i = 0; i < ntohs(response_header->ancount); i++) 
		free(answers[i].rdata);
	
	free(answers);
	free(question.name);

    return 0;
}

void domain_to_dns_format(uint8_t* dns, uint8_t* domain) {	
    memcpy(dns + 1, domain, strlen (domain));
	uint8_t *prev = dns;
	uint8_t count = 0;

	for (size_t i = 0; i < strlen (domain); i++) {
        if (domain[i] == '.') {
            *prev = count;
            prev = dns + i + 1;
            count = 0;
        } else
        	count++;
    }
    *prev = count;
}	


uint32_t addr_to_hex(char *addr) {
	uint32_t bytes[4] = {0};
	char buf[32] = {0};

	/* Лексический анализ IP адреса*/
	if (sscanf(addr, "%3u.%3u.%3u.%3u%31s", bytes, bytes + 1, bytes + 2, bytes + 3, buf) == 4
	 && bytes[0] < 256 && bytes[1] < 256 && bytes[2] < 256 && bytes[3] < 256
	 && strlen(buf) == 0) 
		return inet_addr(addr);
	else 
		return 0;
}


int check_domain(char *domain) {
	regex_t regex;
	int ret = 1;

	/* Лексический анализ домененного имени */
	if (regcomp(&regex, "^([[:alnum:]][A-Za-z0-9-]{0,62}[-.]{1})+[A-Za-z]{2,8}$", REG_EXTENDED)) { 
		fprintf(stderr, "Cannot compile regex\n");
		exit(1);
	}

	ret = regexec(&regex, domain, 0, NULL, 0);

	regfree(&regex);

	return ret;
}


uint8_t* decompress(uint8_t* reader, uint8_t* buffer, int* count) {
    uint8_t* name = (uint8_t*)malloc(256); 
    if (name == NULL) 
        return NULL; 

    uint32_t pos = 0; /* Позиция в декомпрессированном имени */
    int jumped = 0; /* Флаг для указания на переход на другую позицию */
    uint32_t offset; /* Смещение для перехода */

    *count = 1; /* Инициализируем количество шагов чтения */

    name[0] = '\0'; 

    while (*reader != 0) {
        if (*reader >= 0xC0) { // Если встречаем смещение
            offset = (*reader) * 0x100 + *(reader + 1) - 0xC000; 
			/* Вычисляем смещение (соединить два байта смещения, убрать ведущие два бита) 
			C0 0C -> 11000000 00001100 -> 1100000000000000 + 00001100 
			-> 1100000000001100 -> 1100 */
            reader = buffer + offset - 1; /* Переходим на новую позицию в буфере */
            jumped = 1; /* Устанавливаем флаг перехода */
        } else {
            name[pos++] = *reader; /* Записываем символ в декомпрессированное имя */
        }

        reader++; /* Переходим к следующему символу */

        if (!jumped) {
            (*count)++; /* Увеличиваем количество шагов, если не было перехода */
        }
    }

    name[pos] = '\0'; /* Завершаем строку */

    if (jumped) {
        (*count)++; /* Увеличиваем количество шагов, если был переход */
    }

    /* Преобразуем формат 3www6google3com0 в www.google.com */
    int i = 0;
    while (name[i] != '\0') {
        uint8_t repeat = name[i]; /* Получаем количество повторений символа */
        for (int j = 0; j < repeat; j++) {
            name[i] = name[i + 1]; /* Перемещаем символы на одну позицию влево */
            i++;
        }
        name[i] = '.'; /* Добавляем точку между частями имени */
        i++;
    }
    name[i - 1] = '\0'; /* Удаляем последнюю точку */

    return name; 
}